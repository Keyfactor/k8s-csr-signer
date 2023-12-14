/*
Copyright © 2023 Keyfactor

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
	logrtesting "github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"testing"
)

var (
	fixedClock = clock.RealClock{}
)

func CreateCertificateSigningRequest(name types.NamespacedName, status certificates.RequestConditionType, csr, certificate []byte) *certificates.CertificateSigningRequest {
	return &certificates.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
		},
		Spec: certificates.CertificateSigningRequestSpec{
			SignerName: fakeSignerName,
			Request:    csr,
		},
		Status: certificates.CertificateSigningRequestStatus{
			Conditions: []certificates.CertificateSigningRequestCondition{
				{
					Type: status,
				},
			},
			Certificate: certificate,
		},
	}
}

func CreateFakeCreds(name types.NamespacedName) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("public key"),
			"tls.key": []byte("private key"),
		},
	}
}

func CreateFakeConfig(name types.NamespacedName) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name.Name,
			Namespace: name.Namespace,
		},
		Data: map[string]string{
			"commandHostname":                        "fake-hostname.command.com",
			"defaultCertificateTemplate":             "FakeCertTemplate",
			"defaultCertificateAuthorityLogicalName": "FakeCALogicalName",
			"defaultCertificateAuthorityHostname":    "fake-ca.command.com",
			"chainDepth":                             "2",
		},
	}
}

func TestCertificateSigningRequestReconciler_Reconcile(t *testing.T) {
	type testCase struct {
		name                                    types.NamespacedName
		objects                                 []client.Object
		clusterResourceNamespace                string
		expectedResult                          ctrl.Result
		expectedError                           error
		expectedCertificate                     []byte
		credsSecret, configMap, caCertConfigmap types.NamespacedName
		signerBuilder                           signer.Builder
		checkScope                              bool
	}

	namespacedCsrName := types.NamespacedName{Namespace: "ns1", Name: "csr1"}
	namespacedCredsName := types.NamespacedName{Namespace: "ns1", Name: "creds1"}
	namespacedCaCertConfigmapName := types.NamespacedName{Namespace: "ns1", Name: "caCertConfigmap1"}

	tests := map[string]testCase{
		"not-found": {
			name:          namespacedCsrName,
			signerBuilder: &FakeSignerBuilder{},
		},
		"not-approved": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateDenied, nil, nil),
			},
			signerBuilder: &FakeSignerBuilder{},
		},
		"already-signed": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateApproved, nil, fakeSuccessCertificate),
			},
			expectedCertificate: fakeSuccessCertificate,
			signerBuilder:       &FakeSignerBuilder{},
		},
		"no-creds": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateApproved, nil, nil),
			},
			expectedError: fmt.Errorf("failed to get Secret containing Signer credentials, secret name: , reason: secrets \"\" not found"),
			signerBuilder: &FakeSignerBuilder{},
		},
		"no-configmap": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateApproved, nil, nil),
				CreateFakeCreds(namespacedCredsName),
			},
			credsSecret:   namespacedCredsName,
			expectedError: fmt.Errorf("failed to get ConfigMap containing Signer configuration, configmap name: , reason: configmaps \"\" not found"),
			signerBuilder: &FakeSignerBuilder{},
		},
		"no-ca-cert-configmap": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateApproved, nil, nil),
				CreateFakeCreds(namespacedCredsName),
				CreateFakeConfig(namespacedCredsName),
			},
			credsSecret:     namespacedCredsName,
			configMap:       namespacedCredsName,
			caCertConfigmap: namespacedCaCertConfigmapName,
			expectedError:   fmt.Errorf("caSecretName was provided, but failed to get ConfigMap containing CA certificate, configmap name: %q, reason: configmaps %q not found", namespacedCaCertConfigmapName, namespacedCaCertConfigmapName.Name),
			signerBuilder:   &FakeSignerBuilder{},
		},
		"sign-error": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateApproved, fakeCsr, nil),
				CreateFakeCreds(namespacedCredsName),
				CreateFakeConfig(namespacedCredsName),
			},
			credsSecret: namespacedCredsName,
			configMap:   namespacedCredsName,
			signerBuilder: &FakeSignerBuilder{
				errSign: fmt.Errorf("sign error"),
			},
			expectedError: fmt.Errorf("sign error"),
		},
		"success": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateApproved, fakeCsr, nil),
				CreateFakeCreds(namespacedCredsName),
				CreateFakeConfig(namespacedCredsName),
			},
			credsSecret:         namespacedCredsName,
			configMap:           namespacedCredsName,
			signerBuilder:       &FakeSignerBuilder{},
			expectedCertificate: fakeSuccessCertificate,
		},
		"denied": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateDenied, fakeCsr, nil),
				CreateFakeCreds(namespacedCredsName),
				CreateFakeConfig(namespacedCredsName),
			},
			credsSecret:   namespacedCredsName,
			configMap:     namespacedCredsName,
			signerBuilder: &FakeSignerBuilder{},
		},
		"check-scope": {
			name: namespacedCsrName,
			objects: []client.Object{
				CreateCertificateSigningRequest(namespacedCsrName, certificates.CertificateApproved, fakeCsr, nil),
			},
			signerBuilder: &FakeSignerBuilder{},
			checkScope:    true,
			// The fake client does not have a fake SelfSubjectAccessReview API, so we expect an error
			expectedError: fmt.Errorf(" \"\" is invalid: metadata.name: Required value: name is required"),
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				Build()
			controller := CertificateSigningRequestReconciler{
				Client:                   fakeClient,
				ConfigClient:             NewFakeConfigClient(fakeClient),
				Scheme:                   scheme,
				ClusterResourceNamespace: tc.clusterResourceNamespace,
				SignerBuilder:            tc.signerBuilder,
				CheckApprovedCondition:   true,
				Clock:                    fixedClock,
				CredsSecret:              tc.credsSecret,
				ConfigMap:                tc.configMap,
				CaCertConfigmap:          tc.caCertConfigmap,
				CheckServiceAccountScope: tc.checkScope,
			}
			result, err := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.New(t)),
				reconcile.Request{NamespacedName: tc.name},
			)
			if tc.expectedError != nil {
				assertErrorIs(t, tc.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedResult, result, "Unexpected result")

			var csr certificates.CertificateSigningRequest
			err = fakeClient.Get(context.TODO(), tc.name, &csr)
			require.NoError(t, client.IgnoreNotFound(err), "unexpected error from fake client")
			if err == nil {
				assert.Equal(t, tc.expectedCertificate, csr.Status.Certificate)
			}
		})
	}
}

func assertErrorIs(t *testing.T, expectedError, actualError error) {
	if !assert.Error(t, actualError) {
		return
	}
	assert.Equal(t, expectedError.Error(), actualError.Error(), "unexpected error type. expected: %v, got: %v", expectedError, actualError)
}
