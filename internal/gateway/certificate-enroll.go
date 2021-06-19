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

	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"istio.io/api/security/v1alpha1"
)

// CreateCertificate response cert chain
func (k *KeyfactorGateway) CreateCertificate(ctx context.Context,
	req *v1alpha1.IstioCertificateRequest) (*v1alpha1.IstioCertificateResponse, error) {
	metadata, err := keyfactor.ExtractMetadataFromCSR(ctx, req)
	if err != nil {
		sLog.Errorf("cannot extract metadata from request: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "cannot extract metadata from request: %v", err)
	}

	resp, err := k.keyfactorClient.CSRSign(ctx, req.GetCsr(), metadata, false)
	if err != nil {
		sLog.Errorf("cannot request sign CSR to keyfactor api: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "cannot request sign CSR to keyfactor api: %v", err)
	}
	return &v1alpha1.IstioCertificateResponse{
		CertChain: resp.CertificateInformation.Certificates,
	}, nil
}
