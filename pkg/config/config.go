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

package config

import (
	"fmt"

	"github.com/Keyfactor/k8s-proxy/pkg/env"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"github.com/Keyfactor/k8s-proxy/pkg/util"
	"github.com/spf13/viper"
)

var (
	cLog             = klogger.Register("ServerConfig")
	ServiceNameENV   = env.RegisterString("SERVICE_NAME", "k8s-proxy-service")
	NamespaceENV     = env.RegisterString("NAMESPACE", "keyfactor")
	ClusterDomainENV = env.RegisterString("CLUSTER_DOMAIN", "cluster.local")
	PodNameENV       = env.RegisterString("POD_NAME", "k8s-proxy-pod")
	PodIPENV         = env.RegisterString("POD_IP", "k8s-proxy-pod")
)

// ServerConfig contains all configuration of server
type ServerConfig struct {
	// Port server listener port for GPRC Server and Webhook Server
	GRPCPort                        string
	HealthCheckPort                 string
	Environment                     string
	IstioNamespace                  string
	IstioSecretName                 string
	EnableAutoProvisioningIstioCert bool
	Hostname                        string
	ServiceName                     string
	Namespace                       string
	PodName                         string
	ClusterDomain                   string
	PodIP                           string
	MetadataMapping                 map[string]string
	DisableMTLS                     bool
}

//LoadConfig load config from file
func LoadConfig(cfgFile string) *ServerConfig {
	sc := DefaultConfig()

	if cfgFile != "" {
		cLog.Infof("start load config from file: %s", cfgFile)
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("./config")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		cLog.Infof("config file is empty. Load config from default path: %v", viper.ConfigFileUsed())
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println(fmt.Errorf("load keyfactor config from file (%s) got error:%v", viper.ConfigFileUsed(), err))
	}

	err := viper.Unmarshal(sc)

	if err != nil {
		cLog.Errorf("cannot Unmarshal config from file: %v - %v", viper.ConfigFileUsed(), err)
	}

	sc.ClusterDomain = ClusterDomainENV.Get()
	sc.ServiceName = ServiceNameENV.Get()
	sc.Namespace = NamespaceENV.Get()
	sc.PodName = PodNameENV.Get()
	sc.Hostname = util.GetHostName(ServiceNameENV.Get(), NamespaceENV.Get(), ClusterDomainENV.Get())
	sc.PodIP = PodIPENV.Get()

	cLog.Infof("load config successful: \n%#v\n", sc)
	return sc
}

// DefaultConfig get default of ServerConfig
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		GRPCPort:                        "8090",
		IstioNamespace:                  "istio-system",
		EnableAutoProvisioningIstioCert: true,
	}

}
