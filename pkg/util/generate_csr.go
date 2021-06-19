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

package util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
)

var (
	csrLog = klogger.Register("CSR Gen")
)

// CertOptions contains options for generating a new certificate.
type CertOptions struct {
	// Comma-separated hostnames and IPs to generate a certificate for.
	// This can also be set to the identity running the workload,
	// like kubernetes service account.
	Host string

	// Organization for this certificate.
	Org string
}

const keySizeOfRSA = 2048

// GenCSR generates a X.509 certificate sign request and private key with the given options.
func GenCSR(options CertOptions) ([]byte, []byte, error) {

	priv, err := rsa.GenerateKey(rand.Reader, keySizeOfRSA)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA key generation failed (%v)", err)
	}
	template, err := GenCSRTemplate(options)
	if err != nil {
		return nil, nil, fmt.Errorf("CSR template creation failed (%v)", err)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, crypto.PrivateKey(priv))
	if err != nil {
		return nil, nil, fmt.Errorf("CSR creation failed (%v)", err)
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	encodedKey := x509.MarshalPKCS1PrivateKey(priv)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: encodedKey})
	return csr, privPem, err
}

// GenCSRTemplate generates a certificateRequest template with the given options.
func GenCSRTemplate(options CertOptions) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{options.Org},
		},
	}

	if h := options.Host; len(h) > 0 {
		s, err := BuildSubjectAltNameExtension(h)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = []pkix.Extension{*s}
	}

	return template, nil
}

// AppendRootCerts appends root certificates in RootCertFile to the input certificate.
func AppendRootCerts(pemCert []byte, rootCertFile string) ([]byte, error) {
	var rootCerts []byte
	if len(pemCert) > 0 {
		// Copy the input certificate
		rootCerts = make([]byte, len(pemCert))
		copy(rootCerts, pemCert)
	}
	if len(rootCertFile) > 0 {
		csrLog.Infof("append root certificates from %v", rootCertFile)
		certBytes, err := ioutil.ReadFile(rootCertFile)
		if err != nil {
			return rootCerts, fmt.Errorf("failed to read root certificates (%v)", err)
		}
		csrLog.Infof("The root certificates to be appended is: %v", rootCertFile)
		if len(rootCerts) > 0 {
			// Append a newline after the last cert
			rootCerts = []byte(strings.TrimSuffix(string(rootCerts), "\n") + "\n")
		}
		rootCerts = append(rootCerts, certBytes...)
	}
	return rootCerts, nil
}
