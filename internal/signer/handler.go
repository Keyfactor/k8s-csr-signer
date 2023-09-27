// Copyright 2021 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	//capi "k8s.io/api/certificates/v1beta1"
	capi "k8s.io/api/certificates/v1"
	//certificates "k8s.io/api/certificates/v1beta1"
	certificates "k8s.io/api/certificates/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	hanlderLog = klogger.Register("CertificateSigner-Handler")
)

func (c *CertificateController) handleCSR(csr *capi.CertificateSigningRequest) error {
	if !IsCertificateRequestApproved(csr) {
		return nil
	}
	hanlderLog.Infof("Request Certificate - signerName: %s", csr.Spec.SignerName)
	if !strings.Contains(csr.Spec.SignerName, KeyfactorSignerNameScope) {
		hanlderLog.Errorf("Request Certificate - out of signer name scope: %s", csr.Spec.SignerName)
		return fmt.Errorf("Invalid certificate SignerName: %s", csr.Spec.SignerName)
	}

	var usages []string

	for _, usage := range csr.Spec.Usages {
		usages = append(usages, string(usage))
	}

	hanlderLog.Infof("Request Certificate - usages: %v", usages)

	timeoutContext, cancel := context.WithTimeout(context.TODO(), 15*time.Second)
	defer cancel()

	csrMetadata := extractMetadataFromK8SCSRAPI(csr.GetObjectMeta().GetAnnotations())
	hanlderLog.Infof("Request Certificate - extra metadata: %#v", csrMetadata)
	res, err := c.keyfactorClient.CSRSign(timeoutContext, string(csr.Spec.Request), csrMetadata, false)

	if err != nil {
		hanlderLog.Errorf("cannot signing certificate from K8S CSR API: %v", err)
		return fmt.Errorf("cannot signing certificate from K8S CSR API: %v", err)
	}
	certChain := res.CertificateInformation.Certificates
	csr.Status.Certificate = []byte(strings.Join(certChain, ""))

	_, err = c.kubeClient.CertificatesV1().CertificateSigningRequests().UpdateStatus(context.TODO(), csr, v1.UpdateOptions{})

	if err != nil {
		hanlderLog.Errorf("error updating signature for csr: %v", err)
		return fmt.Errorf("error updating signature for csr: %v", err)
	}
	return nil
}

func extractMetadataFromK8SCSRAPI(extra map[string]string) *keyfactor.CSRMetadata {
	meta := &keyfactor.CSRMetadata{}

	for key, value := range extra {
		hanlderLog.Infof("Meta: %s - %v", key, value)
		switch key {
		case "ClusterID":
			meta.ClusterID = value
		case "ServiceName":
			meta.ServiceName = value
		case "PodIP":
			meta.PodIP = value
		case "PodName":
			meta.PodName = value
		case "PodNamespace":
			meta.PodNamespace = value
		case "TrustDomain":
			meta.TrustDomain = value
		}
	}

	return meta
}

// IsCertificateRequestApproved returns true if a certificate request has the
// "Approved" condition and no "Denied" conditions; false otherwise.
func IsCertificateRequestApproved(csr *certificates.CertificateSigningRequest) bool {
	approved, denied := getCertApprovalCondition(&csr.Status)
	return approved && !denied
}

func getCertApprovalCondition(status *certificates.CertificateSigningRequestStatus) (approved bool, denied bool) {
	for _, c := range status.Conditions {
		if c.Type == certificates.CertificateApproved {
			approved = true
		}
		if c.Type == certificates.CertificateDenied {
			denied = true
		}
	}
	return
}
