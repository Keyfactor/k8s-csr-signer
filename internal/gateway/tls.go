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

package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"github.com/Keyfactor/k8s-proxy/pkg/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	hostName          = "keyfactor-k8s.svc.keyfactor.cluster.local"
	serverCertificate = "./certs/server.crt"
	serverPrivateKey  = "./certs/server.key"
	rootCAFile        = "./certs/root-cert.pem"
	clientCertificate = "./certs/client.crt"
	clientPrivateKey  = "./certs/client.key"
	log               = klogger.Register("retrieveServerTLS")
)

func (k *KeyfactorGateway) retrieveServerTLS() (*tls.Certificate, *x509.CertPool, error) {

	// If missing, generate new one
	if _, err := os.Stat(serverCertificate); err != nil {
		log.Infof("starting gen new Server tls certificates")
		if err = k.genTLSCertificateFromKeyfactor(serverPrivateKey, serverCertificate, rootCAFile); err != nil {
			log.Errorf("gen certificate for server got error: %v", err)
			return nil, nil, fmt.Errorf("gen certificate for server got error: %v", err)
		}
		if err = k.genTLSCertificateFromKeyfactor(clientPrivateKey, clientCertificate, rootCAFile); err != nil {
			log.Errorf("gen certificate for client got error: %v", err)
			return nil, nil, fmt.Errorf("gen certificate for client got error: %v", err)
		}
	} else {
		log.Infof("server tls certificate existed.")
	}

	log.Infof("loading tls certificate")
	certificate, err := tls.LoadX509KeyPair(serverCertificate, serverPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load TLS certificate failed: %v", err)
	}

	log.Infof("loading root CA at: %v", rootCAFile)
	rootCertBytes, err := ioutil.ReadFile(rootCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load root-cert failed: %v", err)
	}

	log.Infof("create rootCAPool..")
	rootCAPool := x509.NewCertPool()
	if ok := rootCAPool.AppendCertsFromPEM(rootCertBytes); !ok {
		return nil, nil, fmt.Errorf("append certs from root PEM failed: %v", string(rootCertBytes))
	}
	return &certificate, rootCAPool, nil
}

func (k *KeyfactorGateway) genTLSCertificateFromKeyfactor(keyFile, certFile, caFile string) error {
	if _, err := os.Stat("./certs"); err != nil {
		os.MkdirAll("./certs", 0777)
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	hostNames := []string{k.serverConfig.Hostname, "0.0.0.0", "127.0.0.1"}
	sanIds, err := util.BuildSubjectAltNameExtension(hostNames...)
	if err != nil {
		return fmt.Errorf("cannot generate private key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   k.serverConfig.Hostname,
			Organization: []string{"Keyfactor Inc"},
		},
		DNSNames:        hostNames,
		ExtraExtensions: []pkix.Extension{*sanIds},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	blockCSR := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	csrStr := string(pem.EncodeToMemory(blockCSR))

	log.Infof("CSR for enroll server TLS certficate: %v", csrStr)
	if err != nil {
		return fmt.Errorf("cannot generate CSR: %v", err)
	}

	cxt, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	metadata := &keyfactor.CSRMetadata{
		TrustDomain:  k.serverConfig.ClusterDomain,
		ClusterID:    "Kubernetes",
		PodName:      k.serverConfig.PodName,
		PodNamespace: k.serverConfig.Namespace,
		ServiceName:  k.serverConfig.ServiceName,
		PodIP:        k.serverConfig.PodIP,
	}

	res, err := k.keyfactorClient.CSRSign(cxt, csrStr, metadata, true)
	certChain := res.CertificateInformation.Certificates
	block, _ := pem.Decode([]byte(certChain[0]))
	err = ioutil.WriteFile(certFile, pem.EncodeToMemory(block), 0777)
	if err != nil {
		return fmt.Errorf("save server cert failed: %v", err)
	}
	err = savePEMKey(keyFile, privKey)
	if err != nil {
		return fmt.Errorf("save private key failed: %v", err)
	}

	rootCABlock, _ := pem.Decode([]byte(certChain[len(certChain)-1]))
	err = ioutil.WriteFile(caFile, pem.EncodeToMemory(rootCABlock), 0777)
	if err != nil {
		return fmt.Errorf("save rootCA cert failed: %v", err)
	}
	return nil
}

func savePEMKey(fileName string, key *rsa.PrivateKey) error {
	outFile, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("cannot create file %v - err: %v", fileName, err)
	}
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	if err != nil {
		return fmt.Errorf("cannot writefile file %v - err: %v", fileName, err)
	}
	return nil
}

func (k *KeyfactorGateway) verifyPeer(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer found")
	}

	tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
	}

	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "could not verify peer certificate")
	}

	sLog.Infof("Verify peer mTLS: %+v", tlsAuth.State)
	// Check subject common name against configured Keyfactor's CaName
	if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != k.serverConfig.Hostname {
		return status.Error(codes.Unauthenticated, "invalid subject common name")
	}

	return nil
}
