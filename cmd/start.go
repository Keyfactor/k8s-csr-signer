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

package cmd

import (
	"fmt"
	"net"

	"github.com/Keyfactor/k8s-proxy/internal/gateway"
	"github.com/Keyfactor/k8s-proxy/internal/health"
	"github.com/Keyfactor/k8s-proxy/internal/signer"
	"github.com/Keyfactor/k8s-proxy/pkg/k8s"
	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
)

var (
	startCMD = &cobra.Command{
		Use:   "start",
		Short: "Start Keyfactor Gateway for integrating with Istio",
		Run: func(cmd *cobra.Command, args []string) {
			startKeyfactorGatewayServer()
		},
	}
	cmdLog = klogger.Register("startCMD")
)

func startKeyfactorGatewayServer() error {

	var k8sClient *kubernetes.Clientset
	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", cf.GRPCPort))
	if err != nil {
		return fmt.Errorf("cannot start net listener for server: %v", err)
	}
	cmdLog.Infof("create net listener at: %s", lis.Addr())
	kl, err := keyfactor.New(keyfactorCredential, cf.MetadataMapping)
	if err != nil {
		return fmt.Errorf("cannot create keyfactor client: %v", err)
	}
	cmdLog.Infof("created KeyfactorClient of endpoint: %s", keyfactorCredential.Endpoint)

	if cf.Environment != "Development" {
		cmdLog.Info("creating in cluster kubernetes client...")
		k8sClient, err = k8s.NewInClusterClient()
		if err != nil {
			cmdLog.Errorf("cannot create new Kuberenetes Client: %v", err)
			return fmt.Errorf("cannot create new Kuberenetes Client: %v", err)
		}
	} else {
		cmdLog.Info("creating out of cluster kubernetes client for dev environment...")
		k8sClient, err = k8s.NewTestClient(kubeconfig)
		if err != nil {
			cmdLog.Errorf("cannot create new Kuberenetes Client: %v", err)
			return fmt.Errorf("cannot create new Kuberenetes Client: %v", err)
		}
	}

	keyfactorGateway, err := gateway.NewKeyfactorGateway(kl, cf, keyfactorCredential, k8sClient)

	if err != nil {
		return fmt.Errorf("cannot create Keyfactor Gateway: %v", err)
	}
	stopChan := make(chan struct{})
	errChan := make(chan error)
	defer close(stopChan)

	go func() {

		err := keyfactorGateway.GPRC.Serve(lis)
		if err != nil {
			cmdLog.Errorf("Keyfactor gatewaye got err: %v", err)
		}
		errChan <- err
	}()

	hService := &health.ServiceHealthCheck{
		Addr: cf.HealthCheckPort,
	}

	go func() {
		err := hService.Serve()
		if err != nil {
			cmdLog.Errorf("cannot start health check service: %v", err)
		}
		errChan <- err
	}()

	certificateController := signer.NewCertificateController(k8sClient, kl)

	go certificateController.RunWorker(3, stopChan)

	cmdLog.Infof("started Keyfactor GRPC Gateway at: %v", lis.Addr().String())

	<-errChan
	return fmt.Errorf("keyfactor gateway closed: %v", keyfactorGateway.GPRC.GetServiceInfo())
}
