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

package mock

import (
	"context"

	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	"github.com/stretchr/testify/mock"
)

// KeyfactorClientMock is a mocked object that implements an interface keyfactor Client
type KeyfactorClientMock struct {
	mock.Mock
}

// NewKeyfactorClientMock create mocking keyfactor client
func NewKeyfactorClientMock() *KeyfactorClientMock {
	return new(KeyfactorClientMock)
}

// CSRSign is a method on KeyfactorClientMock that implements some interface
// and just records the activity, and returns what the Mock object tells it to.
func (m *KeyfactorClientMock) CSRSign(ctx context.Context, csrPEM string, metadata *keyfactor.CSRMetadata, isServerTLS bool) (*keyfactor.EnrollResponse, error) {
	m.Called(csrPEM, metadata)
	return nil, nil
}
