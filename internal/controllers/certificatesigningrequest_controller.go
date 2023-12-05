/*
Copyright 2023 The Keyfactor Command Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"github.com/Keyfactor/k8s-csr-signer/internal/signer"
	"github.com/Keyfactor/k8s-csr-signer/pkg/util"
	v1 "k8s.io/api/authorization/v1"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

type CertificateSigningRequestReconciler struct {
	client.Client
	Scheme                                           *runtime.Scheme
	SignerBuilder                                    signer.Builder
	ClusterResourceNamespace                         string
	Clock                                            clock.Clock
	CheckApprovedCondition, CheckServiceAccountScope bool
	CredsSecret, ConfigMap, CaCertConfigmap          types.NamespacedName
}

func (c *CertificateSigningRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	reconcileLog := ctrl.LoggerFrom(ctx)

	meta := signer.K8sMetadata{}

	c.SignerBuilder.Reset()

	// Get the CertificateSigningRequest
	var certificateSigningRequest certificates.CertificateSigningRequest
	if err = c.Get(ctx, req.NamespacedName, &certificateSigningRequest); err != nil {
		if err = client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		reconcileLog.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	if c.CheckServiceAccountScope {
		// Verify that the signerName is available within the scope of the controller's service account
		scopeStatus, err := c.IsIssuerInScope(ctx, certificateSigningRequest.Spec.SignerName)
		if err != nil {
			return ctrl.Result{}, err
		}

		if !scopeStatus.Allowed {
			reconcileLog.Info(fmt.Sprintf("SignerName %q is not in scope of the controller's service account. Ignoring.", certificateSigningRequest.Spec.SignerName))
			return ctrl.Result{}, nil
		}
	}

	// Ignore CertificateSigningRequests that are not approved yet
	if c.CheckApprovedCondition && !util.IsCertificateRequestApproved(certificateSigningRequest) {
		reconcileLog.Info("CertificateSigningRequest has not been approved yet. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateSigningRequests that have already been signed
	if certificateSigningRequest.Status.Certificate != nil {
		reconcileLog.Info("CertificateSigningRequest has already been signed. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Always attempt to update the Ready condition
	defer func() {
		reconcileLog.Info(fmt.Sprintf("Updating CertificateSigningRequest called %q", certificateSigningRequest.GetName()))

		if updateErr := c.Status().Update(ctx, &certificateSigningRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	reconcileLog.Info(fmt.Sprintf("Preparing to sign CSR called %q", certificateSigningRequest.GetName()))

	// Get the credentials secret
	var creds corev1.Secret
	if err = c.Get(ctx, c.CredsSecret, &creds); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get Secret containing Signer credentials, secret name: %s, reason: %v", c.CredsSecret.Name, err)
	}

	// Get the signer configuration
	var config corev1.ConfigMap
	if err = c.Get(ctx, c.ConfigMap, &config); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get ConfigMap containing Signer configuration, configmap name: %s, reason: %v", c.ConfigMap.Name, err)
	}

	// Get the CA certificate
	var root corev1.ConfigMap
	if c.CaCertConfigmap.Name != "" {
		// If the CA secret name is not specified, we will not attempt to retrieve it
		err = c.Get(ctx, c.CaCertConfigmap, &root)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("caSecretName was provided, but failed to get ConfigMap containing CA certificate, configmap name: %q, reason: %v", c.CaCertConfigmap, err)
		}
	}

	// Populate metadata
	meta.ControllerNamespace = c.ClusterResourceNamespace
	meta.ControllerKind = "CertificateSigningRequest"
	meta.ControllerResourceGroupName = "certificatesigningrequests.certificates.k8s.io"
	meta.ControllerReconcileId = string(controller.ReconcileIDFromContext(ctx))
	meta.ControllerResourceName = certificateSigningRequest.GetName()

	// Apply the configuration to the signer builder
	c.SignerBuilder.
		WithContext(ctx).
		WithCredsSecret(creds).
		WithConfigMap(config).
		WithCACertConfigMap(root).
		WithMetadata(meta)

	// Validate that there were no issues with the configuration
	err = c.SignerBuilder.PreFlight()
	if err != nil {
		return ctrl.Result{}, err
	}

	// Sign the certificate
	leafAndChain, err := c.SignerBuilder.Build().Sign(certificateSigningRequest)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Update the certificate status
	certificateSigningRequest.Status.Certificate = leafAndChain

	return ctrl.Result{}, nil
}

func (c *CertificateSigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificates.CertificateSigningRequest{}).
		Complete(c)
}

func (c *CertificateSigningRequestReconciler) IsIssuerInScope(ctx context.Context, issuerName string) (v1.SubjectAccessReviewStatus, error) {
	scopeLog := ctrl.LoggerFrom(ctx)

	ssar := v1.SelfSubjectAccessReview{
		Spec: v1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Group:    "certificates.k8s.io",
				Resource: "signers",
				Name:     issuerName,
				Verb:     "sign", // Check for "sign" verb for the given issuer name
			},
		},
	}

	err := c.Create(ctx, &ssar)
	if err != nil {
		scopeLog.Error(err, "Failed to create SelfSubjectAccessReview")
		return v1.SubjectAccessReviewStatus{}, err
	}

	return ssar.Status, nil
}
