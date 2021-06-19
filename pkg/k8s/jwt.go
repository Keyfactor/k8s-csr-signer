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
	"context"
	"fmt"
	"strings"

	"github.com/Keyfactor/k8s-proxy/pkg/config"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"google.golang.org/grpc/metadata"
	k8sauth "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	bearerTokenPrefix = "Bearer "
	authorizationMeta = "authorization"
	clusterIDMeta     = "clusterid"
)

var (
	aLog = klogger.Register("Kubernetes Authenticate")
)

// KubeJWTAuthenticator authenticates K8s JWTs.
type KubeJWTAuthenticator struct {
	trustDomain string

	// Primary cluster kube client
	kube         *kubernetes.Clientset
	serverConfig *config.ServerConfig
}

// NewKubeJWTAuthenticator creates a new kubeJWTAuthenticator.
func NewKubeJWTAuthenticator(client *kubernetes.Clientset, serverConfig *config.ServerConfig) *KubeJWTAuthenticator {
	return &KubeJWTAuthenticator{
		serverConfig: serverConfig,
		kube:         client,
	}
}

// Authenticate authenticates the call using the K8s JWT from the context.
// Return {<namespace>, <serviceaccountname>} in the targetToken when the validation passes.
// Otherwise, return the error.
// targetToken: the JWT of the K8s service account to be reviewed
// jwtPolicy: the policy for validating JWT.
func (a *KubeJWTAuthenticator) Authenticate(ctx context.Context) ([]string, error) {
	targetJWT, err := extractBearerToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("target JWT extraction error: %v", err)
	}
	aLog.Infof("received K8S JWT from request: %v", targetJWT)
	tokenReview := &k8sauth.TokenReview{
		Spec: k8sauth.TokenReviewSpec{
			Token:     targetJWT,
			Audiences: []string{},
		},
	}
	reviewRes, err := a.kube.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		aLog.Errorf("call kubernetes TokenReview failed: %v", err)
		return nil, fmt.Errorf("call kubernetes TokenReview failed: %v", err)
	}
	aLog.Infof("Kubernetes token review response aud: %v", reviewRes.Spec.Audiences)
	return getTokenReviewResult(reviewRes)
}

func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	aLog.Infof("metadata.FromIncomingContext: %#v", md)
	if !ok {
		return "", fmt.Errorf("no metadata is attached")
	}

	authHeader, exists := md[authorizationMeta]
	if !exists {
		return "", fmt.Errorf("no HTTP authorization header exists")
	}

	for _, value := range authHeader {
		if strings.HasPrefix(value, bearerTokenPrefix) {
			return strings.TrimPrefix(value, bearerTokenPrefix), nil
		}
	}

	return "", fmt.Errorf("no bearer token exists in HTTP authorization header")
}

func getTokenReviewResult(tokenReview *k8sauth.TokenReview) ([]string, error) {
	if tokenReview.Status.Error != "" {
		return nil, fmt.Errorf("the service account authentication returns an error: %v",
			tokenReview.Status.Error)
	}
	// An example SA token:
	// {"alg":"RS256","typ":"JWT"}
	// {"iss":"kubernetes/serviceaccount",
	//  "kubernetes.io/serviceaccount/namespace":"default",
	//  "kubernetes.io/serviceaccount/secret.name":"example-pod-sa-token-h4jqx",
	//  "kubernetes.io/serviceaccount/service-account.name":"example-pod-sa",
	//  "kubernetes.io/serviceaccount/service-account.uid":"ff578a9e-65d3-11e8-aad2-42010a8a001d",
	//  "sub":"system:serviceaccount:default:example-pod-sa"
	//  }

	// An example token review status
	// "status":{
	//   "authenticated":true,
	//   "user":{
	//     "username":"system:serviceaccount:default:example-pod-sa",
	//     "uid":"ff578a9e-65d3-11e8-aad2-42010a8a001d",
	//     "groups":["system:serviceaccounts","system:serviceaccounts:default","system:authenticated"]
	//    }
	// }

	if !tokenReview.Status.Authenticated {
		return nil, fmt.Errorf("the token is not authenticated")
	}

	inServiceAccountGroup := false
	for _, group := range tokenReview.Status.User.Groups {
		if group == "system:serviceaccounts" {
			inServiceAccountGroup = true
			break
		}
	}

	if !inServiceAccountGroup {
		return nil, fmt.Errorf("the token is not a service account")
	}

	// "username" is in the form of system:serviceaccount:{namespace}:{service account name}",
	// e.g., "username":"system:serviceaccount:default:example-pod-sa"
	subStrings := strings.Split(tokenReview.Status.User.Username, ":")
	if len(subStrings) != 4 {
		return nil, fmt.Errorf("invalid username field in the token review result")
	}
	namespace := subStrings[2]
	saName := subStrings[3]
	return []string{namespace, saName}, nil
}
