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

package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Keyfactor/k8s-csr-signer/pkg/util"
	logrtesting "github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/url"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"
	"testing"
	"time"
)

func TestNewCommandSignerBuilder(t *testing.T) {
	signer := NewCommandSignerBuilder()
	if signer == nil {
		t.Error("NewCommandSignerBuilder() should not return nil")
	}
}

func TestCommandSignerBuilder(t *testing.T) {
	signer := &commandSigner{}

	t.Run("WithContext", func(t *testing.T) {
		ctx := ctrl.LoggerInto(context.TODO(), logrtesting.New(t))
		signer.WithContext(ctx)

		if signer.ctx != ctx {
			t.Error("WithContext() should set the context")
		}

		if !signer.logger.Enabled() {
			t.Error("Expected logger to be enabled")
		}
	})

	t.Run("WithCredsSecret", func(t *testing.T) {
		t.Run("BasicAuth", func(t *testing.T) {
			secret := corev1.Secret{
				Type: corev1.SecretTypeBasicAuth,
			}

			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			secret.Data = map[string][]byte{
				"username": []byte("username"),
				"password": []byte("password"),
			}

			signer.WithCredsSecret(secret)

			if len(signer.errs) != 0 {
				t.Error("Expected no errors since secret is not empty")
			}
		})
	})

	t.Run("WithConfigMap", func(t *testing.T) {
		config := corev1.ConfigMap{}

		t.Run("Fail", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			signer.WithConfigMap(config)

			if len(signer.errs) == 0 {
				t.Error("Expected errors since config is empty")
			}
		})

		// Clear errors and config
		signer.Reset()

		t.Run("chainDepth_not_digit", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			config.Data = map[string]string{
				"chainDepth": "not a digit",
			}

			signer.WithConfigMap(config)

			if len(signer.errs) == 0 {
				t.Error("Expected errors since chainDepth is not a digit")
			}
		})

		// Clear errors and config
		signer.Reset()

		t.Run("Success", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			config.Data = map[string]string{
				"commandHostname":                        "fake-hostname.command.com",
				"defaultCertificateTemplate":             "FakeCertTemplate",
				"defaultCertificateAuthorityLogicalName": "FakeCALogicalName",
				"defaultCertificateAuthorityHostname":    "fake-ca.command.com",
				"chainDepth":                             "2",
			}

			signer.WithConfigMap(config)

			if len(signer.errs) != 0 {
				t.Error("Expected no errors since config is not empty")
			}

			assert.Equal(t, "fake-hostname.command.com", signer.hostname)
			assert.Equal(t, "FakeCertTemplate", signer.defaultCertificateTemplate)
			assert.Equal(t, "FakeCALogicalName", signer.defaultCertificateAuthorityLogicalName)
			assert.Equal(t, "fake-ca.command.com", signer.defaultCertificateAuthorityHostname)
			assert.Equal(t, 2, signer.chainDepth)
		})
	})

	t.Run("WithCACertConfigMap", func(t *testing.T) {
		caConfig := corev1.ConfigMap{}

		t.Run("InvalidCert", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			caConfig.Data = map[string]string{
				"caCert.crt": "invalid cert",
			}

			signer.WithCACertConfigMap(caConfig)

			if len(signer.caChain) != 0 {
				t.Error("Expected no CA chain since cert is invalid")
			}
		})

		// Clear errors and config
		signer.Reset()

		t.Run("Success", func(t *testing.T) {
			signer.WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t)))

			certificate, err := generateSelfSignedCertificate()
			if err != nil {
				t.Fatalf("Failed to generate self-signed certificate: %v", err)
			}
			certBytes, err := util.CompileCertificatesToPemBytes([]*x509.Certificate{certificate})
			if err != nil {
				t.Fatalf("Failed to compile certificate to PEM bytes: %v", err)
			}

			caConfig.Data = map[string]string{
				"caCert.crt": string(certBytes),
			}

			signer.WithCACertConfigMap(caConfig)

			if len(signer.caChain) != 1 {
				t.Error("Expected CA chain to have one certificate")
			}

			if len(signer.errs) != 0 {
				t.Error("Expected no errors since config is not empty")
			}
		})
	})
}

func TestCommandSigner(t *testing.T) {
	commandConfig := CommandTestConfig{}
	err := commandConfig.Get(t)
	if err != nil {
		t.Fatal(err)
	}

	signerConfig := corev1.ConfigMap{
		Data: map[string]string{
			"commandHostname":                        commandConfig.hostname,
			"defaultCertificateTemplate":             commandConfig.commandCertificateTemplate,
			"defaultCertificateAuthorityLogicalName": commandConfig.commandCertificateAuthorityLogicalName,
			"defaultCertificateAuthorityHostname":    commandConfig.commandCertificateAuthorityHostname,
			"chainDepth":                             "0",
		},
	}

	caConfig := corev1.ConfigMap{
		Data: map[string]string{
			"caCert.crt": string(commandConfig.caCertBytes),
		},
	}

	dn, err := parseSubjectDN(commandConfig.commandCsrDn, false)
	if err != nil {
		return
	}

	t.Run("BasicAuth", func(t *testing.T) {
		creds := corev1.Secret{
			Type: corev1.SecretTypeBasicAuth,
			Data: map[string][]byte{
				"username": []byte(commandConfig.username),
				"password": []byte(commandConfig.password),
			},
		}

		// Build the signer
		builder := &commandSigner{}
		builder.
			WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t))).
			WithCredsSecret(creds).
			WithConfigMap(signerConfig).
			WithCACertConfigMap(caConfig)

		err = builder.PreFlight()
		if err != nil {
			t.Fatalf("Failed to preflight signer: %v", err)
		}

		signer := builder.Build()

		// Generate a CSR
		csr, _, err := generateCSR(dn.String(), []string{dn.CommonName}, []string{}, []string{})
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}
		request := certificates.CertificateSigningRequest{
			Spec: certificates.CertificateSigningRequestSpec{
				Request: csr,
			},
		}

		signedCertBytes, err := signer.Sign(request)
		if err != nil {
			t.Fatalf("Failed to sign CSR: %v", err)
		}

		// Verify the signed certificate
		certBlock, _ := util.DecodePEMBytes(signedCertBytes)
		if len(certBlock) == 0 {
			t.Fatalf("Failed to decode signed certificate")
		}

		cert, err := x509.ParseCertificate(certBlock[0].Bytes)
		if err != nil {
			t.Fatalf("Failed to parse signed certificate: %v", err)
		}

		if cert.Subject.String() != commandConfig.commandCsrDn {
			t.Error("Signed certificate subject does not match CSR subject")
		}
	})

	// Create supported annotations
	supportedAnnotations := map[string]string{
		"k8s-csr-signer.keyfactor.com/certificateTemplate":             commandConfig.commandCertificateTemplate,
		"k8s-csr-signer.keyfactor.com/certificateAuthorityHostname":    commandConfig.commandCertificateAuthorityHostname,
		"k8s-csr-signer.keyfactor.com/certificateAuthorityLogicalName": commandConfig.commandCertificateAuthorityLogicalName,
		"k8s-csr-signer.keyfactor.com/chainDepth":                      "5",
	}

	t.Run("BasicAuthWithAnnotations", func(t *testing.T) {
		estCreds := corev1.Secret{
			Type: corev1.SecretTypeBasicAuth,
			Data: map[string][]byte{
				"username": []byte(commandConfig.username),
				"password": []byte(commandConfig.password),
			},
		}

		// Clear out existing config for annotation override
		signerConfig = corev1.ConfigMap{
			Data: map[string]string{
				"commandHostname": commandConfig.hostname,
			},
		}

		// Build the signer
		builder := &commandSigner{}
		builder.
			WithContext(ctrl.LoggerInto(context.TODO(), logrtesting.New(t))).
			WithCredsSecret(estCreds).
			WithConfigMap(signerConfig).
			WithCACertConfigMap(caConfig)

		err = builder.PreFlight()
		if err != nil {
			t.Fatalf("Failed to preflight signer: %v", err)
		}

		signer := builder.Build()

		// Generate a CSR
		csr, _, err := generateCSR(dn.String(), []string{dn.CommonName}, []string{}, []string{})
		if err != nil {
			t.Fatalf("Failed to generate CSR: %v", err)
		}
		request := certificates.CertificateSigningRequest{
			Spec: certificates.CertificateSigningRequestSpec{
				Request: csr,
			},
		}

		request.SetAnnotations(supportedAnnotations)

		signedCertBytes, err := signer.Sign(request)
		if err != nil {
			t.Fatalf("Failed to sign CSR: %v", err)
		}

		// Verify the signed certificate
		certBlock, _ := util.DecodePEMBytes(signedCertBytes)
		if len(certBlock) == 0 {
			t.Fatalf("Failed to decode signed certificate")
		}

		cert, err := x509.ParseCertificate(certBlock[0].Bytes)
		if err != nil {
			t.Fatalf("Failed to parse signed certificate: %v", err)
		}

		if cert.Subject.String() != commandConfig.commandCsrDn {
			t.Error("Signed certificate subject does not match CSR subject")
		}
	})
}

type CommandTestConfig struct {
	hostname string
	username string
	password string

	commandCertificateTemplate             string
	commandCertificateAuthorityLogicalName string
	commandCertificateAuthorityHostname    string

	caCertBytes []byte

	commandCsrDn string
}

func (c *CommandTestConfig) Get(t *testing.T) error {
	var errs []error

	// Paths
	pathToCaCert := os.Getenv("COMMAND_CA_CERT_PATH")

	// Command Config
	c.hostname = os.Getenv("COMMAND_HOSTNAME")
	c.username = os.Getenv("COMMAND_USERNAME")
	c.password = os.Getenv("COMMAND_PASSWORD")

	c.commandCertificateTemplate = os.Getenv("COMMAND_CERTIFICATE_TEMPLATE")
	c.commandCertificateAuthorityLogicalName = os.Getenv("COMMAND_CERTIFICATE_AUTHORITY_LOGICAL_NAME")
	c.commandCertificateAuthorityHostname = os.Getenv("COMMAND_CERTIFICATE_AUTHORITY_HOSTNAME")

	// CSR Config
	c.commandCsrDn = "CN=k8s-csr-signer-test.com"

	if pathToCaCert == "" {
		err := errors.New("COMMAND_CA_CERT_PATH environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.hostname == "" {
		err := errors.New("COMMAND_HOSTNAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.username == "" {
		err := errors.New("COMMAND_USERNAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.password == "" {
		err := errors.New("COMMAND_PASSWORD environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.commandCertificateTemplate == "" {
		err := errors.New("COMMAND_CERTIFICATE_TEMPLATE environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.commandCertificateAuthorityLogicalName == "" {
		err := errors.New("COMMAND_CERTIFICATE_AUTHORITY_LOGICAL_NAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	if c.commandCertificateAuthorityHostname == "" {
		err := errors.New("COMMAND_CERTIFICATE_AUTHORITY_HOSTNAME environment variable is not set")
		t.Error(err)
		errs = append(errs, err)
	}

	// Read the CA cert from the file system.
	caCertBytes, err := os.ReadFile(pathToCaCert)
	if err != nil {
		t.Errorf("Failed to read CA cert from file system: %v", err)
		errs = append(errs, err)
	}
	c.caCertBytes = caCertBytes

	return utilerrors.NewAggregate(errs)
}

func generateSelfSignedCertificate() (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func generateCSR(subject string, dnsNames []string, uris []string, ipAddresses []string) ([]byte, *x509.CertificateRequest, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject, false)
	if err != nil {
		return nil, nil, err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	if len(dnsNames) > 0 {
		template.DNSNames = dnsNames
	}

	// Parse and add URIs
	var uriPointers []*url.URL
	for _, u := range uris {
		if u == "" {
			continue
		}
		uriPointer, err := url.Parse(u)
		if err != nil {
			return nil, nil, err
		}
		uriPointers = append(uriPointers, uriPointer)
	}
	template.URIs = uriPointers

	// Parse and add IPAddresses
	var ipAddrs []net.IP
	for _, ipStr := range ipAddresses {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddrs = append(ipAddrs, ip)
	}
	template.IPAddresses = ipAddrs

	// Generate the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return nil, nil, err
	}

	var csrBuf bytes.Buffer
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return nil, nil, err
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, err
	}

	return csrBuf.Bytes(), parsedCSR, nil
}

// Function that turns subject string into pkix.Name
// EG "C=US,ST=California,L=San Francisco,O=HashiCorp,OU=Engineering,CN=example.com"
func parseSubjectDN(subject string, randomizeCn bool) (pkix.Name, error) {
	var name pkix.Name

	if subject == "" {
		return name, nil
	}

	// Split the subject into its individual parts
	parts := strings.Split(subject, ",")

	for _, part := range parts {
		// Split the part into key and value
		keyValue := strings.SplitN(part, "=", 2)

		if len(keyValue) != 2 {
			return pkix.Name{}, asn1.SyntaxError{Msg: "malformed subject DN"}
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		// Map the key to the appropriate field in the pkix.Name struct
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			if randomizeCn {
				name.CommonName = fmt.Sprintf("%s-%s", value, generateRandomString(5))
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}

func generateRandomString(length int) string {
	mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[mathrand.Intn(len(letters))]
	}
	return string(b)
}
