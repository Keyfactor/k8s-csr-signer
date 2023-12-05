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

package util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	certificates "k8s.io/api/certificates/v1"
	"os"
	"strings"
)

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// GetInClusterNamespace Copied from controller-runtime/pkg/leaderelection
func GetInClusterNamespace() (string, error) {
	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	_, err := os.Stat(inClusterNamespacePath)
	if os.IsNotExist(err) {
		return "", errors.New("not running in-cluster")
	} else if err != nil {
		return "", fmt.Errorf("error checking namespace file: %w", err)
	}

	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(namespace), nil
}

// IsCertificateRequestApproved returns true if a certificate request has the
// "Approved" condition and no "Denied" conditions; false otherwise.
func IsCertificateRequestApproved(csr certificates.CertificateSigningRequest) bool {
	approved, denied := getCertApprovalCondition(csr.Status)
	return approved && !denied
}

func getCertApprovalCondition(status certificates.CertificateSigningRequestStatus) (approved bool, denied bool) {
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

// CompileCertificatesToPemBytes takes a slice of x509 certificates and returns a string containing the certificates in PEM format
// If an error occurred, the function logs the error and continues to parse the remaining objects.
func CompileCertificatesToPemBytes(certificates []*x509.Certificate) ([]byte, error) {
	var leafAndChain strings.Builder

	for _, certificate := range certificates {
		err := pem.Encode(&leafAndChain, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})
		if err != nil {
			return make([]byte, 0), err
		}
	}

	return []byte(leafAndChain.String()), nil
}

func DecodePEMBytes(buf []byte) ([]*pem.Block, *pem.Block) {
	var privKey *pem.Block
	var certs []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			privKey = block
		} else {
			certs = append(certs, block)
		}
	}
	return certs, privKey
}
