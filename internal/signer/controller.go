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
	"fmt"
	"strings"

	"time"

	"github.com/Keyfactor/k8s-proxy/pkg/keyfactor"
	klogger "github.com/Keyfactor/k8s-proxy/pkg/logger"
	"golang.org/x/time/rate"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"

	//certificates "k8s.io/api/certificates/v1beta1"
	certificates "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	//certificateslisters "k8s.io/client-go/listers/certificates/v1beta1"
	certificateslisters "k8s.io/client-go/listers/certificates/v1"
)

var (
	signerLogger = klogger.Register("CertificateSigner")
)

const (
	// CertificateControllerName name
	CertificateControllerName = "keyfactor-certificate-signer"
	// KeyfactorSignerNameScope default certificate signerName
	KeyfactorSignerNameScope = "keyfactor.com"
)

// CertificateController contains config for Certificate Signing Request Controller
type CertificateController struct {
	kubeClient      clientset.Interface
	csrLister       certificateslisters.CertificateSigningRequestLister
	csrInformer     cache.SharedIndexInformer
	handler         func(*certificates.CertificateSigningRequest) error
	workqueue       workqueue.RateLimitingInterface
	keyfactorClient keyfactor.SigningClientInterface
}

// NewCertificateController create new Kubernetes Controller to watching Certificate Signing Request
func NewCertificateController(kubeClient clientset.Interface, keyfactorClient keyfactor.SigningClientInterface) *CertificateController {
	// Send events to the apiserver
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(signerLogger.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubeClient.CoreV1().Events("")})

	informerFactory := informers.NewSharedInformerFactory(kubeClient, 0)
	csrInformer := informerFactory.Certificates().V1().CertificateSigningRequests()

	cc := &CertificateController{
		kubeClient: kubeClient,
		workqueue: workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
			workqueue.NewItemExponentialFailureRateLimiter(200*time.Millisecond, 1000*time.Second),
			// 10 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
			&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
		), CertificateControllerName),
		keyfactorClient: keyfactorClient,
		csrInformer:     csrInformer.Informer(),
		csrLister:       csrInformer.Lister(),
	}

	// Manage the addition/update of certificate requests
	csrInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			csr := obj.(*certificates.CertificateSigningRequest)
			if !strings.Contains(csr.Spec.SignerName, KeyfactorSignerNameScope) {
				signerLogger.Warnf("ADD NEW CSR: Out of scope of Keyfactor Signer - %s", csr.Spec.SignerName)
				return
			}

			if IsCertificateRequestApproved(csr) {
				return
			}
			signerLogger.Infof("Adding CSR name '%s', signer '%s'. Waiting for approval...", csr.Name, csr.Spec.SignerName)
		},
		UpdateFunc: func(old, new interface{}) {
			newCSR := new.(*certificates.CertificateSigningRequest)
			oldCSR := old.(*certificates.CertificateSigningRequest)
			signerLogger.Infof("Updating certificate request: NEW - %#v", newCSR.Name)
			if !strings.Contains(newCSR.Spec.SignerName, KeyfactorSignerNameScope) {
				signerLogger.Warnf("Out of scope of Keyfactor Signer - %s", newCSR.Spec.SignerName)
				return
			}

			if IsCertificateRequestApproved(oldCSR) || !IsCertificateRequestApproved(newCSR) {
				return
			}

			signerLogger.Infof("Certificate approved: %s. Waiting for signing ...", newCSR.Name)
			cc.workqueue.Add(newCSR.Name)
		},
		DeleteFunc: func(obj interface{}) {
			csr, ok := obj.(*certificates.CertificateSigningRequest)
			if !strings.Contains(csr.Spec.SignerName, KeyfactorSignerNameScope) {
				signerLogger.Warnf("Deleting CSR: Out of scope of Keyfactor Signer - %s", csr.Spec.SignerName)
				return
			}
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					signerLogger.Infof("Couldn't get object from tombstone %#v", obj)
					return
				}
				csr, ok = tombstone.Obj.(*certificates.CertificateSigningRequest)
				if !ok {
					signerLogger.Infof("Tombstone contained object that is not a CSR: %#v", obj)
					return
				}
			}
			signerLogger.Infof("Deleting certificate request %s", csr.Name)
		},
	})

	cc.handler = cc.handleCSR
	return cc
}

// RunWorker the main goroutine responsible for watching and syncing jobs.
func (cc *CertificateController) RunWorker(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer cc.workqueue.ShutDown()

	go cc.csrInformer.Run(stopCh)

	// Handle timeout for syncing.
	timeout := time.NewTimer(time.Second * 30)
	timeoutCh := make(chan struct{})

	go func() {
		<-timeout.C
		timeoutCh <- struct{}{}
	}()

	signerLogger.Infoln("Waiting cache to be synced. Timeout: 30s")
	if ok := cache.WaitForCacheSync(timeoutCh, cc.csrInformer.HasSynced); !ok {
		signerLogger.Fatalln("Timeout expired during waiting for caches to sync.")
	}

	// Launch workers to process Certificates resources
	for i := 0; i < workers; i++ {
		go wait.Until(cc.worker, time.Second, stopCh)
	}

	signerLogger.Infoln("Starting custom controller.")
	<-stopCh
}

// worker runs a thread that dequeues CSRs, handles them, and marks them done.
func (cc *CertificateController) worker() {
	for cc.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (cc *CertificateController) processNextWorkItem() bool {
	cKey, quit := cc.workqueue.Get()
	if quit {
		return false
	}
	defer cc.workqueue.Done(cKey)

	if err := cc.syncFunc(cKey.(string)); err != nil {
		cc.workqueue.AddRateLimited(cKey)
		if _, ignorable := err.(IgnorableErrorType); !ignorable {
			utilruntime.HandleError(fmt.Errorf("Sync %v failed with : %v", cKey, err))
		} else {
			signerLogger.Infof("Sync %v failed with : %v", cKey, err)
		}
		return true
	}

	cc.workqueue.Forget(cKey)
	return true

}

// maybeSignCertificate will inspect the certificate request and, if it has
// been approved and meets policy expectations, generate an X509 cert using the
// cluster CA assets. If successful it will update the CSR approve subresource
// with the signed certificate.
func (cc *CertificateController) syncFunc(key string) error {
	startTime := time.Now()
	defer func() {
		signerLogger.Infof("Finished syncing certificate request %q (%v)", key, time.Since(startTime))
	}()
	csr, err := cc.csrLister.Get(key)
	if errors.IsNotFound(err) {
		signerLogger.Infof("csr has been deleted: %v", key)
		return nil
	}
	if err != nil {
		return err
	}

	if csr.Status.Certificate != nil {
		// no need to do anything because it already has a cert
		return nil
	}

	// need to operate on a copy so we don't mutate the csr in the shared cache
	csr = csr.DeepCopy()

	return cc.handler(csr)
}

// IgnorableError returns an error that we shouldn't handle (i.e. log) because
// it's spammy and usually user error. Instead we will log these errors at a
// higher log level. We still need to throw these errors to signal that the
// sync should be retried.
func IgnorableError(s string, args ...interface{}) IgnorableErrorType {
	return IgnorableErrorType(fmt.Sprintf(s, args...))
}

type IgnorableErrorType string

func (e IgnorableErrorType) Error() string {
	return string(e)
}
