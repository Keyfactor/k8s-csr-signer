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
	"os"
	"path/filepath"

	"github.com/Keyfactor/k8s-proxy/pkg/config"
	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	// Used for flags.
	cfgFile        string
	credentialFile string
	kubeconfig     string

	cf                  *config.ServerConfig
	keyfactorCredential *keyfactor.ClientCredential

	rootCmd = &cobra.Command{
		Use:   "keyfactor",
		Short: "Keyfactor Kubernetes CLI",
	}
	rootLog = klogger.Register("RootCMD")
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "configFile", "./config/config.yaml",
		"config file (default is ./config/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&credentialFile, "credentialFile",
		"./credentials/credentials.yaml", "keyfactor credentials file (default is ./credentials/credentials.yaml)")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", filepath.Join(homeDir(), ".kube", "config"),
		"(optional) absolute path to the kubeconfig file")
	rootCmd.AddCommand(startCMD)
}

func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}

func initConfig() {
	var err error
	cf = config.LoadConfig(cfgFile)
	keyfactorCredential, err = keyfactor.LoadCredential(credentialFile)
	if err != nil {
		rootLog.Errorf("load keyfactor credentials failed: %v. \nPlease check your kubernetes secret", err)
	}
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
