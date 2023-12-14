# Annotation Overrides for the Command K8s CSR Signer

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/k8s-csr-signer) [![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/keyfactor/k8s-csr-signer?label=release)](https://github.com/keyfactor/k8s-csr-signer/releases) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) [![license](https://img.shields.io/github/license/keyfactor/k8s-csr-signer.svg)]()

The Command K8s CSR Signer allows you to customize the certificate signing process by using annotations. Annotations can be used to override the default configuration of the signer. The following annotations are supported:

### Supported Annotations
Here are the supported annotations that can override the default values:

- **`k8s-csr-signer.keyfactor.com/certificateTemplate`**: Overrides the `defaultCertificateTemplate` field from the Command Configuration.

    ```yaml
    k8s-csr-signer.keyfactor.com/certificateTemplate: "istioAuth-3d"
    ```

- **`k8s-csr-signer.keyfactor.com/certificateAuthorityHostname`**: Specifies the Certificate Authority (CA) hostname name to use, overriding the default CA hostname specified by the `defaultCertificateAuthorityHostname` field from the Command Configuration.

    ```yaml
    k8s-csr-signer.keyfactor.com/certificateAuthorityHostname: "DC-CA.Command.local"
    ```

- **`k8s-csr-signer.keyfactor.com/certificateAuthorityLogicalName`**: Specifies the Certificate Authority (CA) logical name to use, overriding the default CA logical name specified by the `defaultCertificateAuthorityLogicalName` field from the Command Configuration.

    ```yaml
    k8s-csr-signer.keyfactor.com/certificateAuthorityLogicalName: "CommandCA1"
    ```

- **`k8s-csr-signer.keyfactor.com/chainDepth`**: Specifies the chain depth to use, overriding the default chain depth specified by the `chainDepth` field from the Command Configuration.

    ```yaml
    k8s-csr-signer.keyfactor.com/chainDepth: 3
    ```

### Metadata Annotations

The Keyfactor Command K8s CSR Signer also allows you to specify Command Metadata through the use of annotations. Metadata attached to a certificate request will be stored in Command and can be used for reporting and auditing purposes. The syntax for specifying metadata is as follows:
```yaml
metadata.k8s-csr-signer.keyfactor.com/<metadata-field-name>: <metadata-value>
```

Ensure that the metadata specified by the `metadata-field-name` matches a name of a metadata field in Command exactly. If the metadata field name does not match, the CSR enrollment will fail.

### How to Apply Annotations

To apply these annotations, include them in the metadata section of your CertificateSigningRequest resource:

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  annotations:
    k8s-csr-signer.keyfactor.com/certificateTemplate: istioAuth-3d
    k8s-csr-signer.keyfactor.com/certificateAuthorityHostname: DC-CA.Command.local
    k8s-csr-signer.keyfactor.com/certificateAuthorityLogicalName: CommandCA1
    # ... other annotations
spec:
# ... rest of the spec
```