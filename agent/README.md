# Agent

The Agent service runs inside a Confidential Virtual Machine (CVM) and manages the full computation lifecycle: receiving encrypted algorithm and dataset uploads, executing them in isolation, and returning encrypted results. It exposes a gRPC API and communicates with the Manager over an attested TLS channel.

## Configuration

The service is configured using environment variables. Unset variables fall back to their defaults.

### Core

| Variable | Description | Default |
| --- | --- | --- |
| `AGENT_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `debug` |
| `AGENT_VMPL` | Virtual Machine Privilege Level for AMD SEV-SNP attestation (0–3) | `2` |
| `AGENT_GRPC_HOST` | Agent gRPC listen target. `0.0.0.0` uses the default Unix socket at `/run/cocos/agent.sock`; set a TCP address such as `127.0.0.1:7002` to listen on TCP instead | `0.0.0.0` |
| `AGENT_CVM_ID` | Unique identifier for this CVM | `""` |
| `AGENT_CERTS_TOKEN` | Authentication token for the certificate service | `""` |

### Manager gRPC Client

These variables are parsed from `clients.StandardClientConfig` with the `AGENT_CVM_GRPC_` prefix. They configure how the Agent connects back to the Manager/CVM control stream.

| Variable | Description | Default |
| --- | --- | --- |
| `AGENT_CVM_GRPC_URL` | Manager gRPC endpoint | `localhost:7001` |
| `AGENT_CVM_GRPC_TIMEOUT` | Timeout for Manager gRPC requests | `60s` |
| `AGENT_CVM_GRPC_CLIENT_CERT` | Path to client certificate (PEM) used when connecting to the Manager | `""` |
| `AGENT_CVM_GRPC_CLIENT_KEY` | Path to client key (PEM) used when connecting to the Manager | `""` |
| `AGENT_CVM_GRPC_SERVER_CA_CERTS` | Path to CA bundle used to verify the Manager | `""` |

### TLS / Certificates

| Variable | Description | Default |
| --- | --- | --- |
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

The Agent's internal gRPC server listens on the Unix socket `/run/cocos/agent.sock` by default. If `AGENT_GRPC_HOST` is set to a TCP address such as `127.0.0.1:7002`, it listens there instead.

When computations are exposed outside the CVM, that traffic is typically served through the ingress proxy on port `7002`.

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
AGENT_GRPC_HOST=127.0.0.1:7002 \
AGENT_CVM_GRPC_URL=localhost:7001 \
./build/cocos-agent
```

> In production the Agent is baked into the [EOS](https://github.com/ultravioletrs/eos)-based HAL and starts automatically inside the CVM.

## Example

Upload an algorithm, upload a dataset, then retrieve the result using the CLI:

```bash
# Generate a key pair (one-time setup)
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# Point the CLI at the Agent ingress endpoint
export AGENT_GRPC_URL=localhost:7002

# Upload the algorithm
./build/cocos-cli algo ./my_algorithm.py private.pem \
  --algorithm python \
  --requirements ./requirements.txt

# Upload a dataset
./build/cocos-cli data ./dataset.csv private.pem

# Retrieve the encrypted result
./build/cocos-cli result private.pem
```
