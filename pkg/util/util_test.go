package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCompileCertificatesToPemBytes(t *testing.T) {
	// Generate two certificates for testing
	cert1, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate mock certificate: %v", err)
	}
	cert2, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate mock certificate: %v", err)
	}

	tests := []struct {
		name          string
		certificates  []*x509.Certificate
		expectedError bool
	}{
		{
			name:          "No certificates",
			certificates:  []*x509.Certificate{},
			expectedError: false,
		},
		{
			name:          "Single certificate",
			certificates:  []*x509.Certificate{cert1},
			expectedError: false,
		},
		{
			name:          "Multiple certificates",
			certificates:  []*x509.Certificate{cert1, cert2},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err = CompileCertificatesToPemBytes(tt.certificates)
			if (err != nil) != tt.expectedError {
				t.Errorf("expected error = %v, got %v", tt.expectedError, err)
			}
		})
	}
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
