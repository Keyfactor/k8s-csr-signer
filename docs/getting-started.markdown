# Getting Started with the Command Certificate Signing Request Proxy for K8s

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/k8s-csr-signer?label=release)](https://github.com/keyfactor/k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/k8s-csr-signer.svg)]()

## Requirements
* Keyfactor Command
    * [Command](https://www.keyfactor.com/products/command/) (v10.4 +)
* Docker (to build the container)
    * [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/)
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) (v1.11.3 +)
* Kubernetes (v1.19 +)
    * [Kubernetes](https://kubernetes.io/docs/tasks/tools/)
    * [Minikube](https://minikube.sigs.k8s.io/docs/start/)
    * [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
    * [Docker Desktop](https://docs.docker.com/desktop/kubernetes/)
    * [Azure Kubernetes](https://azure.microsoft.com/en-us/products/kubernetes-service)
    * [Amazon EKS](https://aws.amazon.com/eks/)
    * [Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine)
* Helm (to deploy to Kubernetes)
    * [Helm](https://helm.sh/docs/intro/install/) (v3.1 +)

## Getting Started
Install required software and their dependencies if not already present. Additionally, verify that at least one Kubernetes node is running by running the following command:

```shell
kubectl get nodes
```

### 1. Building the Container Image

The Command K8s CSR Signer is distributed as source code, and the container must be built manually. The container image can be built using the following command:
```shell
make docker-build DOCKER_REGISTRY=<your container registry> DOCKER_IMAGE_NAME=keyfactor/k8s-csr-signer
```

###### :pushpin: The container image can be built using Docker Buildx by running `make docker-buildx`. This will build the image for all supported platforms.

### 2. Prepare Credentials and Configuration

1. Create a new namespace for the CSR proxy.
    ```shell
    kubectl create namespace command-signer-system
    ```

2. The Command K8s CSR Signer uses the Command REST API to enroll certificates. Authentication to the Command API is handled using HTTP Basic Authentication.

    * If you want to configure the signer to authenticate to Command using HTTP Basic Auth, create a `kubernetes.io/basic-auth` secret.

      Create a `kubernetes.io/basic-auth` secret containing the username and password. The secret must be created in the same namespace as the Helm chart.

        ```shell
        kubectl -n command-signer-system create secret generic --type=kubernetes.io/basic-auth command-credentials \
            --from-literal=username=<username> \
            --from-literal=password=<password>
        ```

3. The Command K8s CSR Signer uses a K8s ConfigMap to configure how certificates are signed by Command, and how signed certificates are stored back into Kubernetes. A [sample](../command-signer-config.yaml) ConfigMap is provided as a reference.

   The following fields are required:
    * `commandHostname`: The hostname of the Command instance.
    * `chainDepth`: The length of the certificate chain included with the leaf certificate. For example, a value of `0` will include the whole chain up to the root CA, and a value of `2` will include the leaf certificate and one intermediate CA certificate.

    * The following fields can be configured in the ConfigMap and are optional if annotations are used to override the values at runtime:
        * `defaultCertificateTemplate`: The default name of the certificate template to use when enrolling certificates in Command.
        * `defaultCertificateAuthorityLogicalName`: The default name of the certificate authority to use when enrolling certificates.
        * `defaultCertificateAuthorityHostname`: The default hostname of the certificate authority to use when enrolling certificates.

   Create a new ConfigMap resource using the following command:
    ```shell
    kubectl -n command-signer-system apply --from-file=config.yaml
    ```

   As with the Command secret, the Command ConfigMap must be deployed in the same namespace as the Helm chart. All fields in the ConfigMap can be overridden using annotations from the CSR at runtime. See the [Annotation Overrides for the Command K8s CSR Signer](annotations.markdown) guide for more information.

4. If the Command API is configured to use a self-signed certificate or with a certificate signed by an untrusted root, the CA certificate must be provided as a Kubernetes configmap.

   ```shell
   kubectl -n command-signer-system create configmap command-ca-cert --from-file=ca.crt
   ```

### 3. Installation from Helm Chart

The Command K8s CSR Signer is installed using a Helm chart. The chart is available in the [Command K8s CSR Signer Helm repository](https://keyfactor.github.io/k8s-csr-signer/).

1. Add the Helm repository:

    ```bash
    helm repo add command-k8s https://keyfactor.github.io/k8s-csr-signer
    helm repo update
    ```

2. Then, install the chart:

    ```bash
    helm install k8s-csr-signer command-k8s/k8s-csr-signer \
        --namespace command-signer-system \
        --set image.repository=<your container registry>/keyfactor/k8s-csr-signer \
        --set image.tag=<tag> \
        # --set image.pullPolicy=Never # Only required if using a local image \
        --set image.pullPolicy=Never \
        --set command.credsSecretName=command-credentials \
        --set command.configMapName=command-signer-config \
        # --set command.caCertConfigmapName=command-ca-cert # Only required if Command API serves an untrusted certificate
    ```

   1. Modifications can be made by overriding the default values in the `values.yaml` file with the `--set` flag. For example, to add an authorized signer name to the ClusterRole, run the following command:

        ```shell
        helm install k8s-csr-signer command-k8s/k8s-csr-signer \
            --namespace command-signer-system \
            --set image.repository=<your container registry>/keyfactor/k8s-csr-signer \
            --set image.tag=<tag> \
            --set command.credsSecretName=command-credentials \
            --set command.configMapName=command-signer-config \
            --set command.signerNames[0]=internalsigner.com
        ```

   2. Modifications can also be made by modifying the `values.yaml` file directly. For example, to override the
   `signerNames` value, modify the `signerNames` value in the `values.yaml` file:

        ```yaml
        cat <<EOF > override.yaml
        image:
            repository: <your container registry>/keyfactor/k8s-csr-signer
            pullPolicy: Never
            tag: "latest"
        command:
            credsSecretName: command-credentials
            configMapName: command-signer-config
            caCertConfigmapName: command-ca-cert
            signerNames:
                - internalsigner.com/cluster
        EOF
        ```

        Then, use the `-f` flag to specify the `values.yaml` file:

        ```yaml
        helm install k8s-csr-signer command-k8s/k8s-csr-signer \
            -n command-signer-system \
            -f override.yaml
        ```

###### :pushpin: Wildcards are **NOT** supported in the `signerNames` field. If you want to allow all signers, do not specify any signer names.

###### :pushpin: The Command K8s CSR signer uses the `SelfSubjectAccessReview` API to determine if the user has permission to sign the CSR. If the user does not have permission, the signer will ignore the CSR.

### 4. Create a new CertificateSigningRequest resource with the provided sample
A [sample CSR object file](../sample/sample.yaml) is provided to getting started. Create a new CSR resource using the following command. The `request` field contains a Base64 encoded PKCS#10 PEM encoded certificate.
```shell
kubectl apply -f sample/sample.yaml
kubectl get csr
```
To enroll the CSR, it must be approved.
```shell
kubectl certificate approve commandCsrTest
```