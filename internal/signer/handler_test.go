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

package signer

import (
	"context"
	"testing"

	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	keyfactorMock "github.com/Keyfactor/k8s-proxy/pkg/keyfactor/mock"

	"github.com/stretchr/testify/assert"
	v1cert "k8s.io/api/certificates/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sFake "k8s.io/client-go/kubernetes/fake"
)

func TestHandleCSR(t *testing.T) {
	invalidSignerName := "scope-hostname.io/unmatch-name"
	validSignerName := "keyfactor.com/certificate-name"

	testcases := map[string]struct {
		csr                 *v1cert.CertificateSigningRequest
		expectError         string
		expectCSRMetadata   *keyfactor.CSRMetadata
		expectCallKeyfactor bool
	}{
		"UnApproved CSR": {
			csr: &v1cert.CertificateSigningRequest{
				Spec: v1cert.CertificateSigningRequestSpec{
					SignerName: validSignerName,
					Request:    []byte("FAKE_CSR"),
				},
			},
			expectCallKeyfactor: false,
		},
		"UnMatched signerName": {
			csr: &v1cert.CertificateSigningRequest{
				Spec: v1cert.CertificateSigningRequestSpec{
					SignerName: invalidSignerName,
					Request:    []byte("FAKE_CSR"),
				},
				Status: v1cert.CertificateSigningRequestStatus{
					Conditions: []v1cert.CertificateSigningRequestCondition{
						{
							Type:    v1cert.CertificateApproved,
							Reason:  "AutoApproved",
							Message: "TestApproved",
						},
					},
				},
			},
			expectError: "Invalid certificate SignerName: scope-hostname.io/unmatch-name",
		},
		"Should run successful": {
			csr: &v1cert.CertificateSigningRequest{
				Spec: v1cert.CertificateSigningRequestSpec{
					SignerName: validSignerName,
					Request:    []byte("FAKE_CSR"),
					Extra: map[string]v1cert.ExtraValue{
						"ServiceName": []string{"KHOA"},
						"OutOfScope":  []string{"SHOULD_IGNORE"},
					},
				},
				Status: v1cert.CertificateSigningRequestStatus{
					Conditions: []v1cert.CertificateSigningRequestCondition{
						{
							Type:    v1cert.CertificateApproved,
							Reason:  "AutoApproved",
							Message: "TestApproved",
						},
					},
				},
			},
			expectCSRMetadata: &keyfactor.CSRMetadata{
				ServiceName: "KHOA",
			},
			expectCallKeyfactor: true,
		},
	}

	for id, tc := range testcases {
		t.Run(id, func(tsub *testing.T) {
			as := assert.New(t)
			mockClient := keyfactorMock.NewKeyfactorClientMock()

			if tc.expectCallKeyfactor {
				mockClient.On("CSRSign", string(tc.csr.Spec.Request), tc.expectCSRMetadata).Times(1)
			}

			controller := &CertificateController{
				keyfactorClient: mockClient,
				kubeClient:      k8sFake.NewSimpleClientset(),
			}
			csrKube, err := controller.kubeClient.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), tc.csr, v1.CreateOptions{})
			as.Equal(err, nil)

			err = controller.handleCSR(csrKube)

			if tc.expectError != "" {
				as.Error(err, tc.expectError)
				return
			}
			as.Equal(err, nil)
		})
	}
}
