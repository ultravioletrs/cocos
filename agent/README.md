# Agent

The Agent service runs inside a Confidential Virtual Machine (CVM) and manages the full computation lifecycle: receiving encrypted algorithm and dataset uploads, executing them in isolation, and returning encrypted results. It exposes a gRPC API and communicates with the Manager over an attested TLS channel.

## Configuration

The service is configured using environment variables. Unset variables fall back to their defaults.

### Core

| Variable | Description | Default |
| --- | --- | --- |
| `AGENT_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `debug` |
| `AGENT_VMPL` | Virtual Machine Privilege Level for AMD SEV-SNP attestation (0–3) | `2` |
| `AGENT_GRPC_HOST` | gRPC server listen address | `0.0.0.0` |
| `AGENT_CVM_GRPC_HOST` | gRPC host reported to the Manager | `""` |
| `AGENT_CVM_GRPC_PORT` | gRPC listen port | `7001` |
| `AGENT_CVM_ID` | Unique identifier for this CVM | `""` |
| `AGENT_CERTS_TOKEN` | Authentication token for the certificate service | `""` |
| `AGENT_ENABLE_ATLS` | Enable Attestation TLS for secure communication | `true` |

### TLS / Certificates

| Variable | Description | Default |
| --- | --- | --- |
| `AGENT_CVM_GRPC_SERVER_CERT` | Path to gRPC server certificate (PEM) | `""` |
| `AGENT_CVM_GRPC_SERVER_KEY` | Path to gRPC server key (PEM) | `""` |
| `AGENT_CVM_GRPC_SERVER_CA_CERTS` | Path to gRPC server CA certificate | `""` |
| `AGENT_CVM_GRPC_CLIENT_CA_CERTS` | Path to gRPC client CA certificate | `""` |
| `AGENT_CVM_CA_URL` | CA service URL for certificate generation (used with aTLS) | `""` |

### Attestation

| Variable | Description | Default |
| --- | --- | --- |
| `AGENT_MAA_URL` | Microsoft Azure Attestation service URL | `https://sharedeus2.eus2.attest.azure.net` |
| `AGENT_OS_BUILD` | OS build information reported in attestation | `UVC` |
| `AGENT_OS_DISTRO` | OS distribution information reported in attestation | `UVC` |
| `AGENT_OS_TYPE` | OS type information reported in attestation | `UVC` |
| `ATTESTATION_SERVICE_SOCKET` | Unix socket path for the attestation service | `/run/cocos/attestation.sock` |

### Remote Resource Download (Optional)

The Agent can download encrypted algorithms and datasets from remote registries (S3, HTTP/HTTPS) and retrieve decryption keys from a Key Broker Service (KBS) via attestation.

| Variable | Description | Default |
| --- | --- | --- |
| `AWS_REGION` | AWS region for S3 access | `""` |
| `AWS_ACCESS_KEY_ID` | AWS access key ID for S3 authentication | `""` |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key for S3 authentication | `""` |
| `AWS_ENDPOINT_URL` | Custom S3-compatible endpoint URL (e.g., MinIO) | `""` |

> **Note:** The KBS URL is specified in the computation manifest, not as an environment variable. See [TESTING_REMOTE_RESOURCES.md](./TESTING_REMOTE_RESOURCES.md) for details.

## API

### gRPC

The Agent exposes a gRPC API on port `7001` (configurable via `AGENT_CVM_GRPC_PORT`).

| Service | Method | Description |
| --- | --- | --- |
| `Agent` | `Algo` | Upload an encrypted algorithm binary or script |
| `Agent` | `Data` | Upload an encrypted dataset |
| `Agent` | `Result` | Download the encrypted computation result |
| `Agent` | `Attestation` | Retrieve a hardware attestation report |
| `Agent` | `State` | Query the current computation state machine status |

## Deployment

```bash
# Clone and build
git clone git@github.com:ultravioletrs/cocos.git
cd cocos
make agent

# Run with minimal configuration
AGENT_LOG_LEVEL=info \
AGENT_CVM_GRPC_PORT=7002 \
./build/cocos-agent
```

> In production the Agent is baked into the [EOS](https://github.com/ultravioletrs/eos)-based HAL and starts automatically inside the CVM.

## Example

Upload an algorithm, upload a dataset, then retrieve the result using the CLI:

```bash
# Generate a key pair (one-time setup)
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# Upload the algorithm (agent address defaults to localhost:7002)
./build/cocos-cli algo ./my_algorithm.py private.pem \
  --algorithm python \
  --requirements ./requirements.txt

# Upload a dataset
./build/cocos-cli data ./dataset.csv private.pem

# Retrieve the encrypted result
./build/cocos-cli result private.pem
```
