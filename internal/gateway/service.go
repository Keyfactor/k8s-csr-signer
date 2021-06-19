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
	"crypto/tls"
	"fmt"

	"github.com/Keyfactor/k8s-proxy/pkg/config"
	"github.com/Keyfactor/k8s-proxy/pkg/k8s"
	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"k8s.io/client-go/kubernetes"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"istio.io/api/security/v1alpha1"
)

var (
	sLog = klogger.Register("GatewayService")
)

// KeyfactorGateway the Proxy service
type KeyfactorGateway struct {
	v1alpha1.UnimplementedIstioCertificateServiceServer
	// GRPC the server implement based istio signing api
	GPRC *grpc.Server

	keyfactorClient keyfactor.SigningClientInterface
	serverConfig    *config.ServerConfig
	credentials     *keyfactor.ClientCredential
	k8sClient       *kubernetes.Clientset
	authenticator   *k8s.KubeJWTAuthenticator
}

// NewKeyfactorGateway create new KeyfactorGateway service
func NewKeyfactorGateway(keyfactorClient keyfactor.SigningClientInterface, serverConfig *config.ServerConfig,
	credentials *keyfactor.ClientCredential, k8sClient *kubernetes.Clientset) (*KeyfactorGateway, error) {
	k := &KeyfactorGateway{
		keyfactorClient: keyfactorClient,
		serverConfig:    serverConfig,
		credentials:     credentials,
		k8sClient:       k8sClient,
	}
	var err error

	k.authenticator = k8s.NewKubeJWTAuthenticator(k.k8sClient, serverConfig)

	if serverConfig.DisableMTLS {
		err = k.initGRPCServerWithInsecure()
		if err != nil {
			return nil, fmt.Errorf("cannot create new Insecure Keyfactor Gateway: %v", err)
		}
	} else {
		err = k.initGRPCServerWithTLS()
		if err != nil {
			return nil, fmt.Errorf("cannot create new TLS Keyfactor Gateway: %v", err)
		}
	}
	v1alpha1.RegisterIstioCertificateServiceServer(k.GPRC, k)
	return k, nil
}

func (k *KeyfactorGateway) initGRPCServerWithTLS() error {
	sLog.Info("initGRPCServerWithTLS...")
	certificate, rootCAs, err := k.retrieveServerTLS()
	sLog.Info("retrieveServerTLS...")
	if err != nil {
		sLog.Errorf("cannot retrive TLS server: %v", err)
		return fmt.Errorf("cannot retrive TLS server: %v", err)
	}

	err = k.createIstioTLSSecretIfMissing(context.TODO())
	if err != nil {
		return fmt.Errorf("create Istio TLS Secret failed: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*certificate},
		ClientCAs:    rootCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	sLog.Info("tlsConfig...")

	k.GPRC = grpc.NewServer(
		grpc.UnaryInterceptor(k.authenticate),
		grpc.Creds(credentials.NewTLS(tlsConfig)),
	)

	return nil
}

func (k *KeyfactorGateway) initGRPCServerWithInsecure() error {
	sLog.Info("initGRPCServerWithInsecure...")
	k.GPRC = grpc.NewServer()
	return nil
}

func (k *KeyfactorGateway) authenticate(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// mTLS verification
	sLog.Info("Checking peer certificate...")
	err = k.verifyPeer(ctx)
	if err != nil {
		sLog.Errorf("Verify peer got err: %v", err)
		return nil, status.Error(codes.Unauthenticated, "Client TLS certificate is missing or invalid")
	}
	return handler(ctx, req)
}
