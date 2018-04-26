# vault-init

The `vault-init` service automates the process of [initializing](https://www.vaultproject.io/docs/commands/operator/init.html) and [unsealing](https://www.vaultproject.io/docs/concepts/seal.html#unsealing) HashiCorp Vault instances running on [Google Cloud Platform](https://cloud.google.com).

After `vault-init` initializes a Vault server it stores master keys and root tokens, encrypted using [Google Cloud KMS](https://cloud.google.com/kms), to a user defined [Google Cloud Storage](https://cloud.google.com/storage) bucket.

## Usage

The `vault-init` service is designed to be run alongside a Vault server and communicate over local host.

### Kubernetes

Run `vault-init` in the same Pod as the Vault container. See the [vault statefulset](statefulset.yaml) for a complete example.

## Configuration

The vault-init service supports the following environment variables for configuration:

* `CHECK_INTERVAL` - The time in seconds between Vault health checks. (300)
* `GCS_BUCKET_NAME` - The Google Cloud Storage Bucket where the vault master key and root token is stored. 
* `KMS_KEY_ID` - The Google Cloud KMS key ID used to encrypt and decrypt the vault master key and root token.

### Example Values

```
CHECK_INTERVAL="300"
GCS_BUCKET_NAME="vault-storage"
KMS_KEY_ID="projects/my-project/locations/global/keyRings/my-keyring/cryptoKeys/key"
```
