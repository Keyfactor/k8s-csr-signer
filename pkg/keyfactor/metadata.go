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
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"github.com/Keyfactor/k8s-proxy/pkg/util"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/gogo/protobuf/types"
	pb "istio.io/api/security/v1alpha1"
)

var (
	log = klogger.Register("Extract Metadata from CSR")
)

// CSRMetadata Metadata extracted from Istio's CSR
type CSRMetadata struct {
	ClusterID    string
	TrustDomain  string
	PodName      string
	PodNamespace string
	PodIP        string
	ServiceName  string
}

// IstioMetadata the certificate singing metadata carry from xds node
type IstioMetadata struct {
	WorkloadName string   `json:"WorkloadName"`
	ClusterID    string   `json:"ClusterID"`
	WorkloadIPs  []string `json:"WorkloadIPs"`
}

// MappingCustomMetadata create dynnamic metadata based on configure
func (metadata *CSRMetadata) MappingCustomMetadata(metadataConfig map[string]string) map[string]string {
	if metadata.ServiceName == "" && metadata.PodName != "" {
		podSplitted := strings.Split(metadata.PodName, "-")
		metadata.ServiceName = strings.Join(podSplitted[:len(podSplitted)-2], "-")
	}
	metadataPayload := make(map[string]string)
	for key, fieldName := range metadataConfig {
		switch key {
		case "clusterid":
			metadataPayload[fieldName] = metadata.ClusterID
		case "service":
			metadataPayload[fieldName] = metadata.ServiceName
		case "podname":
			metadataPayload[fieldName] = metadata.PodName
		case "podip":
			metadataPayload[fieldName] = metadata.PodIP
		case "podnamespace":
			metadataPayload[fieldName] = metadata.PodNamespace
		case "trustdomain":
			metadataPayload[fieldName] = metadata.TrustDomain
		}
	}
	return metadataPayload
}

// ParseMetadataProtoStruct return Metadata struct from proto message
func ParseMetadataProtoStruct(proto *types.Struct) (*IstioMetadata, error) {
	m := &IstioMetadata{}
	marshaler := &jsonpb.Marshaler{
		EmitDefaults: true,
	}
	str, err := marshaler.MarshalToString(proto)
	if err != nil {
		log.Errorf("parse proto Struct to Json failed: %v", err)
		return nil, fmt.Errorf("parse proto Struct to Json failed: %v", err)
	}
	err = json.Unmarshal([]byte(str), m)
	if err != nil {
		log.Errorf("unmarshal json to Metadata Struct failed: %v", err)
		return nil, fmt.Errorf("unmarshal json to Metadata Struct failed: %v", err)
	}
	return m, nil
}

// ExtractMetadataFromCSR extract metadata from request CSR context and proto message
func ExtractMetadataFromCSR(ctx context.Context, request *pb.IstioCertificateRequest) (*CSRMetadata, error) {
	meta := &CSRMetadata{}

	istioMetadata, err := ParseMetadataProtoStruct(request.Metadata)
	if err == nil {
		meta.ClusterID = istioMetadata.ClusterID
		meta.PodName = istioMetadata.WorkloadName
		if len(istioMetadata.WorkloadIPs) > 0 {
			meta.PodIP = istioMetadata.WorkloadIPs[0]
		}
		log.Infof("Retrived PodName, ClusterID, PodIP from CSR request: %#v", meta)
	} else {
		log.Warningf("cannot parse istio metadata from proto.struct: %v", err)
	}

	pemBlock, _ := pem.Decode([]byte(request.GetCsr()))
	if pemBlock == nil {
		return nil, fmt.Errorf("csr request is invalid: %v", request.GetCsr())
	}

	cert, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse CSR from request: %v", err)
	}
	meta = parseFromCertificateRequestExt(meta, cert)
	return meta, nil
}

func parseFromCertificateRequestExt(meta *CSRMetadata, cert *x509.CertificateRequest) *CSRMetadata {
	ids, err := util.ExtractIDs(cert.Extensions)

	if err == nil && len(ids) != 0 {
		if spiffeData, err := util.ExtractSPIFFE(ids[0]); err == nil {
			meta.TrustDomain = spiffeData.TrustDomain
			meta.PodNamespace = spiffeData.Namespace
			meta.ServiceName = strings.Replace(spiffeData.ServiceAccount, "-service-account", "", 1)
			log.Infof("Retrive TrustDomain, PodNamespace, ServiceName from SPIFFE URI: %#v", meta)
			return meta
		}
	}
	log.Warningf("cannot extract SAN URI from request: %v -\n %+v", err, cert)
	log.Warningf("CSR raw: \n%#v", cert)
	return meta
}
