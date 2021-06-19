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

package util

import (
	"fmt"
	"net/url"
	"strings"
)

type SpiffeStruct struct {
	TrustDomain    string
	ServiceAccount string
	Namespace      string
}

func ExtractSPIFFE(peerID string) (*SpiffeStruct, error) {

	s := &SpiffeStruct{}

	u, err := url.Parse(peerID)
	if err != nil {
		return nil, fmt.Errorf("cannot extract SPIFFE ID: %v", err)
	}

	s.TrustDomain = u.Hostname()
	splitedPath := strings.Split(u.Path, "/")
	s.Namespace = splitedPath[2]
	s.ServiceAccount = splitedPath[4]
	return s, nil
}
