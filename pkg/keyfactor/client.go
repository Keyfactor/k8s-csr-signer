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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	kf "github.com/Keyfactor/keyfactor-go-client-sdk/api/keyfactor"
	"net/http"
	"net/url"
	"path"
	"strings"
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
		clientLog.Errorf("error encoding json data: %v", err)
		return nil, fmt.Errorf("error encoding json data: %v", err)
	}

	u, err := url.Parse(cl.credentials.Endpoint)

	if err != nil {
		clientLog.Errorf("invalid caAddress: %v (%v)", cl.credentials.Endpoint, err)
		return nil, fmt.Errorf("invalid caAddress: %v (%v)", cl.credentials.Endpoint, err)
	}

	u.Path = path.Join(u.Path, cl.credentials.EnrollPath)
	enrollCSRPath := u.String()

	clientLog.Infof("start sign Keyfactor CSR request to: %v", enrollCSRPath)

	xKeyfactorRequestedWith := "APIClient"
	xKeyfactorApiVersion := "1"
	xCertificateFormat := "PEM"

	// parse the URL
	parsedURL, err := url.Parse(cl.credentials.Endpoint)
	if err != nil {
		clientLog.Errorf("error parsing url: %v %v", cl.credentials.Endpoint, err)
	}

	// extract the hostname
	hostname := parsedURL.Hostname()
	hostnameParts := strings.Split(hostname, ".")

	var domain = ""
	if len(hostnameParts) >= 2 {
		domain = strings.Join(hostnameParts[len(hostnameParts)-2:], ".")
	} else {
		clientLog.Errorf("Invalid hostname: %v", hostname)
	}

	// grab the Base64-encoded part of the authToken
	authTokenParts := strings.Split(cl.credentials.AuthToken, " ")
	if len(authTokenParts) != 2 || authTokenParts[0] != "Basic" {
		clientLog.Errorf("invalid authentication token")
	}

	// decode the base64 username and password
	decodedAuthToken, err := base64.StdEncoding.DecodeString(authTokenParts[1])
	if err != nil {
		clientLog.Errorf("error decoding Base64: %v", err)
	}

	credentials := strings.Split(string(decodedAuthToken), ":")
	if len(credentials) != 2 {
		clientLog.Errorf("invalid basicAuth credentials format")
	}

	// extract the username and password
	username := credentials[0]
	password := credentials[1]

	// create a configuration object
	config := make(map[string]string)
	config["host"] = hostname
	config["username"] = username
	config["password"] = password
	config["domain"] = domain

	configuration := kf.NewConfiguration(config)
	if configuration == nil {
		clientLog.Errorf("configuration %v failed: %v", cl.credentials.Endpoint, err)
	}

	// create a client
	client := kf.NewAPIClient(configuration)
	if client == nil {
		clientLog.Errorf("unable to establish Keyfactor client: %v %v", cl.credentials.Endpoint, err)
	}

	includesChain := true

	// convert the stringMap to a map[string]interface{} using json.Marshal and json.Unmarshal.
	metadataMap := make(map[string]interface{})
	jsonData, err := json.Marshal(metadata.MappingCustomMetadata(cl.metadataConfiguration))
	err = json.Unmarshal(jsonData, &metadataMap)

	time := time.Now().UTC()

	req := &kf.ModelsEnrollmentCSREnrollmentRequest{
		CSR:                        csrPEM,
		CertificateAuthority:       &cl.credentials.CaName,
		IncludeChain:               &includesChain,
		Metadata:                   metadataMap,
		AdditionalEnrollmentFields: nil,
		Timestamp:                  &time,
		Template:                   &cl.credentials.CaTemplate,
		SANs:                       nil,
		AdditionalProperties:       nil,
	}

	resp, httpResp, err := client.EnrollmentApi.EnrollmentPostCSREnroll(context.Background()).XCertificateformat(xCertificateFormat).Request(*req).XKeyfactorRequestedWith(xKeyfactorRequestedWith).XKeyfactorApiVersion(xKeyfactorApiVersion).Execute()

	if err != nil {
		clientLog.Errorf("could not request to KeyfactorCA server: %v %v", cl.credentials.Endpoint, err)
		return nil, fmt.Errorf("could not request to KeyfactorCA server: %v %v", cl.credentials.Endpoint, err)
	}

	status := httpResp.StatusCode

	if status == http.StatusOK {
		mapResp, _ := resp.ToMap()
		jsonData, err := json.Marshal(mapResp)
		if err != nil {
			clientLog.Errorf("could not decode response data from KeyfactorCA: %v", err)
			return nil, fmt.Errorf("could not decode response data from KeyfactorCA: %v", err)
		}

		var jsonResponse EnrollResponse
		json.Unmarshal(jsonData, &jsonResponse)

		jsonResponse.CertificateInformation.Certificates = getCertFromResponse(&jsonResponse)
		return &jsonResponse, nil
	}

	return nil, fmt.Errorf("request failed with status: %v, message: %v", status, err)
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
