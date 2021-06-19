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
	"fmt"

	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"github.com/spf13/viper"
)

var (
	creLog = klogger.Register("KeyfactorCredential")
)

// ClientCredential config meta for KeyfactorCA client
type ClientCredential struct {
	// Endpoint address of certificate authorization
	Endpoint string

	// CaName Name of certificate authorization
	CaName string

	// Using for authentication header
	AuthToken string

	// CaTemplate Certificate Template for enroll the new one Default is Istio
	CaTemplate string

	// AppKey ApiKey from Api Setting
	AppKey string

	// EnrollPath api path to Enroll CSR Request
	EnrollPath string

	ProvisioningAppKey   string
	ProvisioningTemplate string
}

// LoadCredential create and response default config
func LoadCredential(creFilePath string) (*ClientCredential, error) {

	c := &ClientCredential{
		EnrollPath:           "/KeyfactorAPI/Enrollment/CSR",
		CaTemplate:           "Istio",
		ProvisioningTemplate: "K8SProxy",
	}

	if creFilePath != "" {
		creLog.Infof("start load credential from file: %s", creFilePath)
		// Use config file from the flag.
		viper.SetConfigFile(creFilePath)
	} else {
		viper.AddConfigPath("./credentials")
		viper.SetConfigName("credential")
		viper.SetConfigType("yaml")
		creLog.Infof("keyfactor credential file is empty. Load credential from default path: %v", viper.ConfigFileUsed())
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		creLog.Errorf("load keyfactor credential from file (%s) got error:%v", viper.ConfigFileUsed(), err)
		return nil, fmt.Errorf("load keyfactor credential from file (%s) got error:%v", viper.ConfigFileUsed(), err)
	}

	err := viper.Unmarshal(c)

	if err != nil {
		creLog.Errorf("cannot Unmarshal credential from file: %v - %v", viper.ConfigFileUsed(), err)
		return nil, fmt.Errorf("cannot Unmarshal credential from file: %v - %v", viper.ConfigFileUsed(), err)
	}

	return c, nil
}
