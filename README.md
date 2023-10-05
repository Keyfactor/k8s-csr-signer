# k8s-csr-signer
## api-client

Signer for Kubernetes CSR signing API that passes certificate requests to the Keyfactor Web API for signing with a trusted enterprise CA

<!-- add integration specific information below -->
*** 

## Use Cases

This signer operates within the [kubernetes certificate signing request API](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/) and listens for approved CSRs designated for the signer (by default, it matches CSRs with &quot;keyfactor.com/*&quot;). This allows workloads within the cluster or Istio service mesh to obtain trusted identity certificates from an enterprise PKI while providing InfoSec and OpSec teams with insight into the certificates being issued and control over the certificate issuance requirements and content.

## Configuration

1. Configure your Keyfactor environment with an account, API application, and certificate template for enrollment. Information can be found in the Keyfactor reference guide.

2. Create the following string metadata fields in your Keyfactor instance:
- Cluster
- Service
- PodName
- PodIP
- PodNamespace
- TrustDomain

3. Clone this repository or download and unzip the binary release to a suitable location in your cluster control plane.

4. Install the following tools and their dependencies, if not already present:

* Docker (to build the container)
    * [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* Kubernetes (v1.19 +)
    * [Kubernetes](https://kubernetes.io/docs/tasks/tools/) or [Minikube](https://minikube.sigs.k8s.io/docs/start/)
    * Or [Kubernetes with Docker Desktop](https://docs.docker.com/desktop/kubernetes/)
* Helm (to deploy Kubernetes)
    * [Helm](https://helm.sh/docs/intro/install/) (v3.1 +)

5. Open credentials/credentials.yaml and enter the following information:
\# Endpoint of Keyfactor Platform  
endPoint: "http://192.168.0.24"  
\# Name of certificate authority for enrollment  
caName: "Keyfactor.thedemodrive.com\\Keyfactor Test Drive CA 2 "  
\# Basic auth credentials for authentication header: "Basic ...."  
authToken: "Basic RE9NQUlOXFVzZXI6UGFzc3dvcmQ="  
\# API path to enroll new certificate from Keyfactor  
enrollPath: "/KeyfactorAPI/Enrollment/CSR"  
\# Certificate Template for Istio certificate enrollment  
caTemplate: "KubernetesNode"
\# CA Template for auto provisioning TLS server / client certificates  
provisioningTemplate: "KubernetesNode"

6. Create the keyfactor namespace with these credentials as a secret:  
kubectl create namespace keyfactor  
kubectl create secret generic keyfactor-credentials -n keyfactor --from-file credentials/credentials.yaml

7. Install Keyfactor signer with helm  
helm package charts  
helm install keyfactor-k8s -n keyfactor ./keyfactor-kubernetes-0.0.1.tgz -f charts/values.yaml

8. When the pod in the keyfactor namespace is up, you can test the configuration with the provided sample CSR. Note that depending on your selected template and Keyfactor configuration, this may not represent a valid request.  
kubectl apply -f sample/test-csr.yaml  
kubectl approve TestABCDEFNAME

After a few seconds, you should be able to see two certificates issued in your Keyfactor instance: one for the pod created in the keyfactor namespace to communicate via mTLS within the cluster, and one from the sample CSR (if the CSR issuance failed, your Keyfactor instance will reflect that instead).


***

### License
[Apache](https://apache.org/licenses/LICENSE-2.0)
