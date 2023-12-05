# v2.0.0
## Features

### Reconciler Controller
- Refactored K8s `CertificateSigningRequest` controller to use a Reconciler pattern using [controller-runtime](https://pkg.go.dev/sigs.k8s.io/controller-runtime)
- Changed retrieval of authentication, configuration, and CA root certificate to use the Kubernetes API instead of reading from a file
- Added support for out-of-cluster deployments using the Kubernetes API

### Runtime Customization
- Added support for customizing the certificate signing process using annotations

### Documentation
- Added updated documentation for deploying the Command CSR Signer v2.0
- Added updated documentation for using the Command CSR Signer v2.0 with Istio

### Testing
- Added unit tests for the Reconciler controller
- Added unit tests for the CSR Signer

### Actions
- Added GitHub Actions for building and testing the Command CSR Signer
- Added GitHub Actions for releasing the Command CSR Signer