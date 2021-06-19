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
	"fmt"
	"io/ioutil"

	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	istioLog = klogger.Register("IstioSecret")
)

func (k *KeyfactorGateway) createIstioTLSSecretIfMissing(ctx context.Context) error {

	if !k.serverConfig.EnableAutoProvisioningIstioCert {
		return nil
	}
	istioLog.Infof("Provisioning TLS Client Secret for Istio ...")
	istioLog.Infof("Namespace = '%v', SecretName = '%v'", k.serverConfig.IstioNamespace, k.serverConfig.IstioSecretName)
	existedSecret, err := k.k8sClient.CoreV1().Secrets(k.serverConfig.IstioNamespace).Get(ctx, k.serverConfig.IstioSecretName, v1.GetOptions{})

	if existedSecret.Name != "" {
		istioLog.Infof("Istio TLS Client secret is existed: '%v'", existedSecret.Name)
		return nil
	}

	if err != nil {
		clientPrivate, err := ioutil.ReadFile(clientPrivateKey)
		if err != nil {
			return fmt.Errorf("read client private key (%v) failed: %v", clientPrivateKey, err)
		}
		clientCert, err := ioutil.ReadFile(clientCertificate)
		if err != nil {
			return fmt.Errorf("read client cert (%v) failed: %v", clientCertificate, err)
		}
		caCert, err := ioutil.ReadFile(rootCAFile)
		if err != nil {
			return fmt.Errorf("read ca cert (%v) failed: %v", rootCAFile, err)
		}

		namespace := &corev1.Namespace{
			ObjectMeta: v1.ObjectMeta{
				Name: k.serverConfig.IstioNamespace,
			},
		}
		if _, err = k.k8sClient.CoreV1().Namespaces().Create(ctx, namespace, v1.CreateOptions{}); err != nil {
			istioLog.Infof("Namespace (%v) is existed: %v", k.serverConfig.IstioNamespace, err)
		}

		secret := &corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Name: k.serverConfig.IstioSecretName,
				Labels: map[string]string{
					"app": k.serverConfig.ServiceName,
					"env": k.serverConfig.Environment,
				},
				Namespace: k.serverConfig.IstioNamespace,
			},
			StringData: map[string]string{
				"client-key.pem":  string(clientPrivate),
				"client-cert.pem": string(clientCert),
				"cacert.pem":      string(caCert),
			},
		}

		s, err := k.k8sClient.CoreV1().Secrets(k.serverConfig.IstioNamespace).Create(ctx, secret, v1.CreateOptions{})
		if err != nil {
			istioLog.Errorf("create TLS CLIENT secret for Istio failed: %v", err)
			return fmt.Errorf("create TLS CLIENT secret for Istio failed: %v", err)
		}
		log.Infof("create TLS CLIENT secret for Istio successful: %v", s.Name)
	}

	return nil
}
