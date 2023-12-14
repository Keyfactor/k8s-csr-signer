# Testing the Command CSR Signer Source Code

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/k8s-csr-signer?label=release)](https://github.com/keyfactor/k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/k8s-csr-signer.svg)]()

The test cases for the controller require a set of environment variables to be set. These variables are used to
authenticate to a Command API server and to enroll a certificate. The test cases are run using the `make test` command.

The following environment variables must be exported before testing the controller:
- **COMMAND_HOSTNAME** - The hostname of the Command instance.
- **COMMAND_USERNAME** - The username to authenticate to Command.
- **COMMAND_PASSWORD** - The password to authenticate to Command.
- **COMMAND_CA_CERT_PATH** - The path to the CA certificate of the Command API server in PEM format.
- **COMMAND_CERTIFICATE_TEMPLATE** - The certificate template to use when enrolling a certificate.
- **COMMAND_CERTIFICATE_AUTHORITY_HOSTNAME** - The hostname of the Certificate Authority (CA) to use when enrolling a certificate.
- **COMMAND_CERTIFICATE_AUTHORITY_LOGICAL_NAME** - The logical name of the Certificate Authority (CA) to use when enrolling a certificate.
