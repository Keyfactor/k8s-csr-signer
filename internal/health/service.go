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

package health

import (
	"fmt"

	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"github.com/valyala/fasthttp"
)

var (
	log = klogger.Register("HealthCheckLog")
)

// ServiceHealthCheck create a health check service
type ServiceHealthCheck struct {
	Addr string
}

// Serve start listen health check
func (s *ServiceHealthCheck) Serve() error {
	address := fmt.Sprintf("[::]:%s", s.Addr)
	log.Infof("start health check at: %v", address)
	if err := fasthttp.ListenAndServe(address, fasthttp.CompressHandler(s.requestHandler)); err != nil {
		log.Fatalf("Error in ListenAndServe: %s", err)
		return fmt.Errorf("Error in ListenAndServe: %s", err)
	}
	return nil
}

func (s *ServiceHealthCheck) requestHandler(ctx *fasthttp.RequestCtx) {
	ctx.SetStatusCode(fasthttp.StatusOK)
	fmt.Fprintf(ctx, "OK!")
	ctx.SetContentType("text/plain; charset=utf8")
}
