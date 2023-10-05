# k8s-csr-signer test setup

Once Docker Desktop, kubernetes, and Helm are installed, run the following commands in CMD at the base of the repo:

Create a Docker image for the application
```shell
docker build -t signercsr:latest .
```
Navigate to Docker Desktop. Inside the 'Images' tab, click on the singercsr image and select "Run" in the upper left-hand corner to create a container for the image.

Package the Helm charts. 
```shell
helm package charts
```
Create a Kubernetes secret named "keyfactor-credentials" and populate it with data from the file "../credentials/credentials.yaml".
```shell
kubectl create secret generic keyfactor-credentials --from-file credentials/credentials.yaml
```

Perform a dry run of the Helm installation. The below Helm command tries to install a Helm release named "testsigner" from the Helm chart archive file "keyfactor-kubernetes-1.0.0.tgz" with configuration overrides from the file "override.yaml". The --dry-run flag means it won't actually apply the changes to the cluster but will generate the Kubernetes manifest files and redirect the output to "dryrun.yaml."
```shell
cd charts
helm install testsigner keyfactor-kubernetes-1.0.0.tgz -f override.yaml --dry-run > dryrun.yaml
```

Installs the Helm release named "testsigner" from the Helm chart archive file "keyfactor-kubernetes-1.0.0.tgz" with configuration overrides from the file "override.yaml." This time, it performs the actual installation.
```shell
helm uninstall testsigner
helm install testsigner keyfactor-kubernetes-1.0.0.tgz -f override.yaml
```

Check the pod's configuration and current status.
```shell
kubectl describe pod
```

When the pod in the keyfactor namespace is up, test the configuration with the provided sample CSR. Note that depending on your selected template and Keyfactor configuration, this may not represent a valid request.  
```shell
kubectl apply -f sample/test-csr.yaml  
kubectl approve TestABCDEFNAME
kubectl describe certificatesigningrequest TestABCDEFNAME
```
If the status TestABCDEFNAME is 'Approve,Issued,' then the configuration was successful.