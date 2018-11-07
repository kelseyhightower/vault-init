# vault-init

The `vault-init` service automates the process of [initializing](https://www.vaultproject.io/docs/commands/operator/init.html) and [unsealing](https://www.vaultproject.io/docs/concepts/seal.html#unsealing) HashiCorp Vault instances running on either the [Google Cloud Platform](https://cloud.google.com) or [Amazon Web Services](https://aws.amazon.com).

After `vault-init` initializes a Vault server it stores master keys and root tokens.  For GCE it encrypted using [Google Cloud KMS](https://cloud.google.com/kms), to a user defined [Google Cloud Storage](https://cloud.google.com/storage) bucket.
For AWS it encrypts using [AWS KMS](https://aws.amazon.com/kms), to a user defined [AWS S3 bucket](https://aws.amazon.com/s3)

## Usage

The `vault-init` service is designed to be run alongside a Vault server and communicate over local host.

### Kubernetes

Run `vault-init` in the same Pod as the Vault container. See the [vault statefulset](statefulset.yaml) for a complete example.

## Configuration

The vault-init service supports the following environment variables for configuration:

* `CHECK_INTERVAL` - The time in seconds between Vault health checks. (300)
* `GCS_BUCKET_NAME` - The Google Cloud Storage Bucket where the vault master key and root token is stored.
* `S3_BUCKET_NAME` - The Amazon Web Service S3 Bucket where the vault master key and root token is stored. 
* `KMS_KEY_ID` - The Google Cloud/Amazon Web Service KMS key ID used to encrypt and decrypt the vault master key and root token.
* `CLOUD_SERVICE` - GCP for Google Cloud Platform, AWS for Amazon Web Services

### Example Values

Google Cloud Platform
```
CHECK_INTERVAL="300"
GCS_BUCKET_NAME="vault-storage"
KMS_KEY_ID="projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/key"
CLOUD_SERVICE="gcp"
```

Amazon Web Services
```
CHECK_INTERVAL="300"
S3_BUCKET_NAME="vault-storage"
KMS_KEY_ID="arn:aws:kms:us-east-1:614683232738:key/a34faa6b-c865-485a-9cfc-2862ee721dfc"
CLOUD_SERVICE="aws"
```

### Google Cloud IAM &amp; Permissions

The `vault-init` service uses the official Google Cloud Golang SDK. This means
it supports the common ways of [providing credentials to GCP][cloud-creds].

To use this service, the service account must have the following minimum
scope(s):

```text
https://www.googleapis.com/auth/cloudkms
https://www.googleapis.com/auth/devstorage.read_write
```

Additionally, the service account must have the following minimum role(s):

```text
roles/cloudkms.cryptoKeyEncrypterDecrypter
roles/storage.objectAdmin OR roles/storage.legacyBucketWriter
```

For more information on service accounts, please see the
[Google Cloud Service Accounts documentation][service-accounts].

[cloud-creds]: https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application
[service-accounts]: https://cloud.google.com/compute/docs/access/service-accounts

### Amazon Web Service IAM Permissions

The `vault-init` service uses the official Amazon Web Service Golang SDK. This means
it supports the common ways of [providing credentials to AWS][cloud-creds].

To use this service, the IAM Role or IAM User must be added to the IAM Encryption Key [Key Users](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html#key-policy-default-allow-users) list.
Then the AWS Access Keys must be passed down into the container, or an IAM role must be attached to it via [kube2iam](https://github.com/jtblin/kube2iam) or as an instance IAM role.
