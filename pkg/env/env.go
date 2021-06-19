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

package env

import (
	"strings"

	"github.com/spf13/viper"
)

// E struct contains environment value
type E struct {
	name         string
	defaultValue string
}

// Register new env
func RegisterString(name string, defaultValue string) *E {
	viper.BindEnv(name)
	return &E{
		name:         name,
		defaultValue: defaultValue,
	}
}

func (e *E) Get() string {
	envValue := viper.GetString(e.name)
	if envValue != "" {
		return strings.TrimSpace(envValue)
	}
	return e.defaultValue
}
