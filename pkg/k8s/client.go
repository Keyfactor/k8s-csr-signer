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

package k8s

import (
	"fmt"
	"os"

	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	k8sLogger = klogger.Register("K8S_Client")
)

// NewInClusterClient create new kubernetes client
func NewInClusterClient() (*kubernetes.Clientset, error) {
	conf, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("create config failed: %v", err)
	}
	k8sLogger.Infof("get kubernetes config in cluster: %v", conf)

	client, err := kubernetes.NewForConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client failed: %v", err)
	}
	return client, nil
}

// NewTestClient create a Kubernetes Client out of Cluster
func NewTestClient(kubeconfig string) (*kubernetes.Clientset, error) {
	k8sLogger.Infof("NewTestClient: load kubeconfig from: %v", kubeconfig)
	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		k8sLogger.Errorf("load kubeconfig from: %v failed: %v", kubeconfig, err)
		return nil, fmt.Errorf("load kubeconfig from: %v failed: %v", kubeconfig, err)
	}
	// create the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		k8sLogger.Errorf("create kubernetes client failed: %v", err)
		return nil, fmt.Errorf("create kubernetes client failed: %v", err)
	}
	return client, nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
