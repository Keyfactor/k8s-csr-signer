package signer

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Keyfactor/k8s-csr-signer/pkg/util"
	"github.com/Keyfactor/keyfactor-go-client-sdk/api/keyfactor"
	"github.com/go-logr/logr"
	certificates "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strconv"
	"strings"
	"time"
)

// commandSigner implements both Signer and Builder interfaces
var _ Builder = &commandSigner{}
var _ Signer = &commandSigner{}

const (
	enrollmentPEMFormat = "PEM"
	annotationPrefix    = "k8s-csr-signer.keyfactor.com/"
)

type Builder interface {
	Reset() Builder
	WithContext(ctx context.Context) Builder
	WithCredsSecret(corev1.Secret) Builder
	WithConfigMap(corev1.ConfigMap) Builder
	WithCACertConfigMap(corev1.ConfigMap) Builder
	PreFlight() error
	Build() Signer
}

type Signer interface {
	Sign(csr certificates.CertificateSigningRequest) ([]byte, error)
}

type commandSigner struct {
	ctx    context.Context
	logger logr.Logger
	creds  corev1.Secret

	// Given from config
	hostname                               string
	defaultCertificateTemplate             string
	defaultCertificateAuthorityLogicalName string
	defaultCertificateAuthorityHostname    string
	chainDepth                             int

	// Computed
	errs              []error
	caChain           []*x509.Certificate
	preflightComplete bool

	basicAuthRestClient *keyfactor.APIClient
}

func NewCommandSignerBuilder() Builder {
	return &commandSigner{}
}

func (s *commandSigner) Reset() Builder {
	s.errs = make([]error, 0)
	s.preflightComplete = false
	return s
}

func (s *commandSigner) WithContext(ctx context.Context) Builder {
	s.ctx = ctx
	s.logger = log.FromContext(ctx)
	return s
}

func (s *commandSigner) WithCredsSecret(secret corev1.Secret) Builder {
	if secret.Type == corev1.SecretTypeBasicAuth {
		s.logger.Info("Found BasicAuth secret. Using BasicAuth authentication")

		_, ok := secret.Data["username"]
		if !ok {
			s.errs = append(s.errs, errors.New("username not found in secret data"))
		}

		_, ok = secret.Data["password"]
		if !ok {
			s.errs = append(s.errs, errors.New("password not found in secret data"))
		}
	} else {
		s.errs = append(s.errs, errors.New("secret type is not TLS or BasicAuth"))
	}

	s.creds = secret
	return s
}

func (s *commandSigner) WithConfigMap(config corev1.ConfigMap) Builder {
	if host, ok := config.Data["commandHostname"]; ok && host != "" {
		s.hostname = config.Data["commandHostname"]
	} else {
		s.errs = append(s.errs, errors.New("commandHostname not found in config map data"))
	}

	if defaultCertificateTemplate, ok := config.Data["defaultCertificateTemplate"]; ok && defaultCertificateTemplate != "" {
		s.defaultCertificateTemplate = defaultCertificateTemplate
	}

	if defaultCertificateAuthorityLogicalName, ok := config.Data["defaultCertificateAuthorityLogicalName"]; ok && defaultCertificateAuthorityLogicalName != "" {
		s.defaultCertificateAuthorityLogicalName = defaultCertificateAuthorityLogicalName
	}

	if defaultCertificateAuthorityHostname, ok := config.Data["defaultCertificateAuthorityHostname"]; ok && defaultCertificateAuthorityHostname != "" {
		s.defaultCertificateAuthorityHostname = defaultCertificateAuthorityHostname
	}

	if chainDepth, ok := config.Data["chainDepth"]; ok && chainDepth != "" {
		var err error
		s.chainDepth, err = strconv.Atoi(chainDepth)
		if err != nil {
			s.errs = append(s.errs, errors.New("chainDepth is not an integer"))
		}
	}

	return s
}

func (s *commandSigner) WithCACertConfigMap(config corev1.ConfigMap) Builder {
	if len(config.Data) == 0 {
		return s
	}

	// There is no requirement that the CA certificate is stored under a specific key in the secret, so we can just
	// iterate over the map and effectively set the caCertBytes to the last value in the map
	var caCertBytes string
	for _, caCertBytes = range config.Data {
	}

	// Try to decode caCertBytes as a PEM formatted block
	caChainBlocks, _ := util.DecodePEMBytes([]byte(caCertBytes))
	if len(caChainBlocks) > 0 {
		var caChain []*x509.Certificate
		for _, block := range caChainBlocks {
			// Parse the PEM block into an x509 certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				s.errs = append(s.errs, err)
				return s
			}

			caChain = append(caChain, cert)
		}

		s.caChain = caChain
	}

	s.logger.Info(fmt.Sprintf("Found %d CA certificates in the CA certificate config map", len(s.caChain)))

	return s
}

func (s *commandSigner) PreFlight() error {
	var err error

	s.basicAuthRestClient, err = s.newBasicAuthClient()
	if err != nil {
		s.errs = append(s.errs, err)
	}

	s.logger.Info("Preflight complete")
	s.preflightComplete = true
	return utilerrors.NewAggregate(s.errs)
}

func (s *commandSigner) newBasicAuthClient() (*keyfactor.APIClient, error) {
	// Create Command API Client
	commandConfig := keyfactor.NewConfiguration(make(map[string]string))

	if commandConfig.Host == "" {
		commandConfig.Host = s.hostname
	}

	username, ok := s.creds.Data["username"]
	if !ok || len(username) == 0 {
		return nil, errors.New("username not found in secret data")
	}

	password, ok := s.creds.Data["password"]
	if !ok || len(password) == 0 {
		return nil, errors.New("password not found in secret data")
	}

	commandConfig.BasicAuth.UserName = string(username)
	commandConfig.BasicAuth.Password = string(password)

	// If the CA certificate is provided, add it to the Command configuration
	commandConfig.SetCaCertificates(s.caChain)

	s.logger.Info("Creating Command REST API client with basic auth credentials")

	// Create Command API Client
	client := keyfactor.NewAPIClient(commandConfig)
	if client == nil {
		return nil, fmt.Errorf("failed to create Command REST API client")
	}

	return client, nil
}

func (s *commandSigner) Build() Signer {
	if !s.preflightComplete {
		s.logger.Error(fmt.Errorf("preflight not complete"), "preflight must be completed before building signer")
		return nil
	}

	return s
}

func (s *commandSigner) Sign(csr certificates.CertificateSigningRequest) ([]byte, error) {
	annotations := csr.GetAnnotations()

	parsedCsr, err := parseCSR(csr.Spec.Request)
	if err != nil {
		return nil, err
	}

	// Log the common metadata of the CSR
	s.logger.Info(fmt.Sprintf("Found CSR wtih DN %q and %d DNS SANs, %d IP SANs, and %d URI SANs", parsedCsr.Subject, len(parsedCsr.DNSNames), len(parsedCsr.IPAddresses), len(parsedCsr.URIs)))

	// Create a Command CSR enrollment request for initialization
	enroll := keyfactor.ModelsEnrollmentCSREnrollmentRequest{}
	enroll.SetTimestamp(time.Now())
	enroll.SetIncludeChain(true)
	enroll.SetCSR(string(csr.Spec.Request))

	// Set default fields from config map - Will be overwritten by annotations if present
	if s.defaultCertificateTemplate != "" {
		enroll.SetTemplate(s.defaultCertificateTemplate)
	}
	certificateAuthorityHostname := s.defaultCertificateAuthorityHostname
	certificateAuthorityLogicalName := s.defaultCertificateAuthorityLogicalName

	// Set overrides from annotations
	certificateTemplate, ok := annotations[annotationPrefix+"certificateTemplate"]
	if ok && certificateTemplate != "" {
		s.logger.Info(fmt.Sprintf("Using the %q certificate template from CSR annotations", certificateTemplate))
		enroll.SetTemplate(certificateTemplate)
	}

	overrideCertificateAuthorityHostname, ok := annotations[annotationPrefix+"certificateAuthorityHostname"]
	if ok && overrideCertificateAuthorityHostname != "" {
		s.logger.Info(fmt.Sprintf("Using the %q certificate authority hostname from CSR annotations", overrideCertificateAuthorityHostname))
		certificateAuthorityHostname = overrideCertificateAuthorityHostname
	}

	overrideCertificateAuthorityLogicalName, ok := annotations[annotationPrefix+"certificateAuthorityLogicalName"]
	if ok && overrideCertificateAuthorityLogicalName != "" {
		s.logger.Info(fmt.Sprintf("Using the %q certificate authority logical name from CSR annotations", overrideCertificateAuthorityLogicalName))
		certificateAuthorityLogicalName = overrideCertificateAuthorityLogicalName
	}

	chainDepthStr, ok := annotations[annotationPrefix+"chainDepth"]
	if ok {
		chainDepth, err := strconv.Atoi(chainDepthStr)
		if err == nil {
			s.logger.Info(fmt.Sprintf("Using \"%d\" as chain depth from annotation", chainDepth))
			s.chainDepth = chainDepth
		}
	}

	// Construct CA name from hostname and logical name
	var caBuilder strings.Builder
	if certificateAuthorityHostname != "" {
		caBuilder.WriteString(certificateAuthorityHostname)
		caBuilder.WriteString("\\")
	}
	caBuilder.WriteString(certificateAuthorityLogicalName)
	enroll.SetCertificateAuthority(caBuilder.String())

	// Final preflight check
	if enroll.GetTemplate() == "" {
		return nil, errors.New("certificate template was not found - either set the defaultCertificateTemplate in the config map or specify the certificateTemplate annotation")
	}
	if enroll.GetCertificateAuthority() == "" {
		return nil, errors.New("certificate authority was not found - either set the defaultCertificateAuthorityLogicalName and defaultCertificateAuthorityHostname in the config map or specify the certificateAuthorityLogicalName and certificateAuthorityHostname annotations")
	}

	s.logger.Info(fmt.Sprintf("Enrolling CSR with Command using the %q certificate template and the %q CA", enroll.GetTemplate(), enroll.GetCertificateAuthority()))

	// Enroll certificate
	certificateObject, _, err := s.basicAuthRestClient.EnrollmentApi.EnrollmentPostCSREnroll(context.Background()).Request(enroll).XCertificateformat(enrollmentPEMFormat).Execute()
	if err != nil {
		detail := "error enrolling certificate with Command. verify that the certificate template, certificate authority, and credentials are correct"

		var bodyError *keyfactor.GenericOpenAPIError
		ok = errors.As(err, &bodyError)
		if ok {
			detail += fmt.Sprintf(" - %s", string(bodyError.Body()))
		}

		s.logger.Error(err, detail)

		return nil, fmt.Errorf(detail)
	}

	leafAndChain, err := getCertificatesFromCertificateInformation(certificateObject.CertificateInformation)
	if err != nil {
		s.logger.Error(err, fmt.Sprintf("error getting certificate from Command response: %s", err.Error()))
		return nil, err
	}

	// Then, construct the PEM list according to chainDepth

	/*
	   chainDepth = 0 => whole chain
	   chainDepth = 1 => just the leaf
	   chainDepth = 2 => leaf + issuer
	   chainDepth = 3 => leaf + issuer + issuer
	   etc
	*/

	// The two scenarios where we want the whole chain are when chainDepth is 0 or greater than the length of the whole chain
	var pemChain []byte
	if s.chainDepth == 0 || s.chainDepth > len(leafAndChain) {
		s.chainDepth = len(leafAndChain)
	}
	for i := 0; i < s.chainDepth; i++ {
		pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafAndChain[i].Raw})...)
	}

	s.logger.Info(fmt.Sprintf("Successfully enrolled certificate with Command and built leaf and chain to depth %d", s.chainDepth))

	// Return the certificate and chain in PEM format
	return pemChain, nil
}

func getCertificatesFromCertificateInformation(commandResp *keyfactor.ModelsPkcs10CertificateResponse) ([]*x509.Certificate, error) {
	var certBytes []byte

	for _, cert := range commandResp.Certificates {
		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			return nil, errors.New("failed to parse certificate PEM")
		}

		certBytes = append(certBytes, block.Bytes...)
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
