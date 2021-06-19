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

package keyfactor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
)

var (
	clientLog = klogger.Register("Client")
)

// SigningClientInterface interface client of keyfactor
type SigningClientInterface interface {
	CSRSign(ctx context.Context, csrPEM string, metadata *CSRMetadata, isServerTLS bool) (*EnrollResponse, error)
}

// CaClient struct to define http client for KeyfactorCA
type CaClient struct {
	Client                *http.Client
	credentials           *ClientCredential
	metadataConfiguration map[string]string
}

type keyfactorRequestPayload struct {
	CSR                  string            `json:"CSR"`
	CertificateAuthority string            `json:"CertificateAuthority"`
	IncludeChain         bool              `json:"IncludeChain"`
	TimeStamp            string            `json:"TimeStamp"`
	Template             string            `json:"Template"`
	Metadata             map[string]string `json:"Metadata"`
}

// EnrollResponse response structure for keyfactor server
type EnrollResponse struct {
	CertificateInformation struct {
		SerialNumber       string      `json:"SerialNumber"`
		IssuerDN           string      `json:"IssuerDN"`
		Thumbprint         string      `json:"Thumbprint"`
		KeyfactorID        int         `json:"KeyfactorID"`
		KeyfactorRequestID int         `json:"KeyfactorRequestId"`
		Certificates       []string    `json:"Certificates"`
		RequestDisposition string      `json:"RequestDisposition"`
		DispositionMessage string      `json:"DispositionMessage"`
		EnrollmentContext  interface{} `json:"EnrollmentContext"`
	} `json:"CertificateInformation"`
	Metadata struct {
		ClusterID       string `json:"ClusterID"`
		Service         string `json:"Service"`
		PodNamespace    string `json:"PodNamespace"`
		PodName         string `json:"PodName"`
		PodIP           string `json:"PodIP"`
		TrustDomain     string `json:"TrustDomain"`
		TrustDomainData string `json:"TrustDomainData"`
		Cluster         string `json:"Cluster"`
		KMSTestMetadata string `json:"KMSTestMetadata"`
	} `json:"Metadata"`
}

// New create a CA client for KeyFactor CA.
func New(credentials *ClientCredential, metadataConfiguration map[string]string) (SigningClientInterface, error) {
	c := &CaClient{
		credentials:           credentials,
		metadataConfiguration: metadataConfiguration,
	}

	err := c.createTLSClient()
	if err != nil {
		return nil, fmt.Errorf("cannot create TLS client for keyfactor: %v", err)
	}

	return c, nil
}

func (cl *CaClient) createTLSClient() error {
	// Load the system default root certificates.
	pool, err := x509.SystemCertPool()
	if err != nil {
		clientLog.Errorf("could not get SystemCertPool: %v", err)
		return fmt.Errorf("could not get SystemCertPool: %v", err)
	}

	if pool == nil {
		clientLog.Info("System cert pool is nil, create a new cert pool")
		pool = x509.NewCertPool()
	}

	tlsConfig := &tls.Config{
		RootCAs: pool,
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	cl.Client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	return nil
}

// CSRSign calls KeyFactor CA to sign a CSR.
func (cl *CaClient) CSRSign(ctx context.Context, csrPEM string,
	metadata *CSRMetadata, isServerTLS bool) (*EnrollResponse, error) {

	payload := &keyfactorRequestPayload{
		CSR:                  csrPEM,
		CertificateAuthority: cl.credentials.CaName,
		IncludeChain:         true,
		Template:             cl.credentials.CaTemplate,
		TimeStamp:            time.Now().UTC().Format(time.RFC3339),
		Metadata:             metadata.MappingCustomMetadata(cl.metadataConfiguration),
	}

	if isServerTLS {
		payload.Template = cl.credentials.ProvisioningTemplate
	}

	bytesRepresentation, err := json.Marshal(payload)
	clientLog.Infof("payload body: %v", string(bytesRepresentation))
	if err != nil {
		clientLog.Errorf("error encode json data: %v", err)
		return nil, fmt.Errorf("error encode json data: %v", err)
	}

	u, err := url.Parse(cl.credentials.Endpoint)

	if err != nil {
		clientLog.Errorf("invalid caAddress: %v (%v)", cl.credentials.Endpoint, err)
		return nil, fmt.Errorf("invalid caAddress: %v (%v)", cl.credentials.Endpoint, err)
	}

	u.Path = path.Join(u.Path, cl.credentials.EnrollPath)
	enrollCSRPath := u.String()

	clientLog.Infof("start sign Keyfactor CSR request to: %v", enrollCSRPath)
	requestCSR, err := http.NewRequest("POST", enrollCSRPath, bytes.NewBuffer(bytesRepresentation))

	if err != nil {
		return nil, fmt.Errorf("cannot create request with url: %v", enrollCSRPath)
	}

	requestCSR.Header.Set("authorization", cl.credentials.AuthToken)
	requestCSR.Header.Set("x-keyfactor-requested-with", "APIClient")

	if isServerTLS {
		requestCSR.Header.Set("x-Keyfactor-appKey", cl.credentials.ProvisioningAppKey)
	} else {
		requestCSR.Header.Set("x-Keyfactor-appKey", cl.credentials.AppKey)
	}
	requestCSR.Header.Set("x-certificateformat", "PEM")
	requestCSR.Header.Set("Content-Type", "application/json")

	res, err := cl.Client.Do(requestCSR)
	if err != nil {
		clientLog.Errorf("could not request to KeyfactorCA server: %v %v", cl.credentials.Endpoint, err)
		return nil, fmt.Errorf("could not request to KeyfactorCA server: %v %v", cl.credentials.Endpoint, err)
	}
	defer res.Body.Close()
	status := res.StatusCode

	if status == http.StatusOK {
		jsonResponse := &EnrollResponse{}
		err := json.NewDecoder(res.Body).Decode(&jsonResponse)

		if err != nil {
			clientLog.Errorf("could not decode response data from KeyfactorCA: %v", err)
			return nil, fmt.Errorf("could not decode response data from KeyfactorCA: %v", err)
		}
		jsonResponse.CertificateInformation.Certificates = getCertFromResponse(jsonResponse)
		return jsonResponse, nil
	}

	var errorMessage interface{}
	err = json.NewDecoder(res.Body).Decode(&errorMessage)
	if err != nil {
		clientLog.Errorf("cannot decode error message from keyfactorCA: %v", err)
	}
	clientLog.Errorf("request failed with status: %v, message: %v", status, errorMessage)
	return nil, fmt.Errorf("request failed with status: %v, message: %v", status, errorMessage)
}

func getCertFromResponse(jsonResponse *EnrollResponse) []string {

	template := "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n"
	var certChains []string
	for _, certStr := range jsonResponse.CertificateInformation.Certificates {

		block, _ := pem.Decode([]byte(fmt.Sprintf(template, certStr)))
		certChains = append(certChains, string(pem.EncodeToMemory(block)))
	}

	clientLog.Infof("keyfactor response %v certificates in certchain.", len(certChains))

	return certChains
}

func isotimestring(t time.Time) string {
	var tz string
	zName, zOffset := t.Zone()
	if zName == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", zOffset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), tz)
}
