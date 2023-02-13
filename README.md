# k8s-csr-signer
## api-client

Signer for Kubernetes CSR signing API that passes certificate requests to the Keyfactor Command Web API for signing with
a trusted enterprise CA.

<!-- add integration specific information below -->
*** 

## Use Cases

This signer operates within the [kubernetes certificate signing request API](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/) 
and listens for approved CSRs designated for the signer. This allows workloads within the cluster or Istio service mesh 
to obtain trusted identity certificates from an enterprise PKI while providing InfoSec and OpSec teams with insight into 
the certificates being issued and control over the certificate issuance requirements and content.

**NOTE: By default, the signer listens for approved CSRs that match `keyfactor.com/*`**

## Configuration

1. Configure your Keyfactor environment with an account, API application, and certificate template for enrollment. 
Information can be found in the Keyfactor reference guide.

2. Create the following string metadata fields in your Keyfactor instance:
   - Cluster
   - Service
   - PodName
   - PodIP
   - PodNamespace
   - TrustDomain

3. Clone this repository or download and unzip the binary release to a suitable location in your cluster control plane.

4. Install kubectl, helm, and their dependencies if not already present.

5. Open `credentials/credentials.yaml` and enter the following information:

| Field                | Description                                                              | Example                                                 |
|----------------------|--------------------------------------------------------------------------|---------------------------------------------------------|
| endPoint             | The URL of your Keyfactor Command instance.                              | https://192.168.0.24                                    |
| caName               | Name of certificate authority for enrollment.                            | `Keyfactor.thedemodrive.com\\Keyfactor Test Drive CA 2` |
| authToken            | The base64-encoded Basic Auth credentials for the Keyfactor Command API. | `Basic RE9NQUlOXFVzZXI6UGFzc3dvcmQ=`                    |
| enrollPath           | API path to enroll new certificate from Keyfactor Command.               | `/KeyfactorAPI/Enrollment/CSR`                          |
| caTemplate           | Certificate template for Istio certificate enrollment.                   | `KubernetesNode`                                        |
| appKey               | The API key for the API application.                                     | `uYl+FKUbuFpRWg==`                                      |
| provisioningAppKey   | ApiKey from Api Setting, to enroll certificates for Istio.               | `uYl+FKUbuFpRWg==`                                      |
| provisioningTemplate | CA Template for auto provisioning TLS server / client certificates.      | `KubernetesNode`                                        |

6. Create the Keyfactor namespace with these credentials as a secret:
```bash
kubectl create namespace keyfactor  
kubectl create secret generic keyfactor-credentials -n keyfactor --from-file credentials/credentials.yaml 
```

7. Install Keyfactor signer with helm
```bash
helm package charts  
helm install keyfactor-k8s -n keyfactor ./keyfactor-kubernetes-0.0.1.tgz -f charts/values.yaml
```

8. When the pod in the `keyfactor` namespace is up, you can test the configuration with the provided sample CSR. 
Note that depending on your selected template and Keyfactor configuration, this may not represent a valid request.
```bash
kubectl apply -f sample/test-csr.yaml  
kubectl approve TestABCDEFNAME
```
After a few seconds, you should be able to see two certificates issued in your Keyfactor instance: one for the pod 
created in the `keyfactor` namespace to communicate via mTLS within the cluster, and one from the sample CSR (if the CSR 
issuance failed, your Keyfactor Command instance will reflect that instead).

***

### License
[Apache](https://apache.org/licenses/LICENSE-2.0)
