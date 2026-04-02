# Ingress Proxy

The Ingress Proxy controls inbound network traffic into the Confidential Virtual Machine (CVM). It sits in front of the Agent's gRPC endpoint and establishes Attestation TLS (aTLS) connections, ensuring that only callers who have verified the CVM's hardware attestation can communicate with the Agent.

## Overview

When a caller (e.g., the CLI or an orchestrator) connects to the Agent, the connection first goes through the ingress proxy. The proxy:

1. Presents an aTLS certificate backed by live hardware attestation evidence
2. Forwards verified connections to the Agent backend at `http://localhost:7001`
3. Optionally fetches certificates from a CA service when `AGENT_CVM_CA_URL` is set

If no Confidential Computing platform is detected (e.g., in a development environment), aTLS is disabled and the proxy passes traffic through without attestation.

Logs are forwarded to the log-forwarder service over a Unix socket.

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `COCOS_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`). Also accepts `AGENT_LOG_LEVEL` | `info` |
| `COCOS_INGRESS_BACKEND` | Backend URL the proxy forwards verified traffic to | `http://localhost:7001` |
| `AGENT_CVM_CA_URL` | CA service URL for aTLS certificate generation | `""` |
| `AGENT_CVM_ID` | CVM identifier sent to the CA service | `""` |
| `AGENT_CERTS_TOKEN` | Authentication token for the CA service | `""` |
| `AGENT_MAA_URL` | Microsoft Azure Attestation service URL | `https://sharedeus2.eus2.attest.azure.net` |
| `AGENT_OS_BUILD` | OS build info for Azure attestation | `UVC` |
| `AGENT_OS_DISTRO` | OS distro info for Azure attestation | `UVC` |
| `AGENT_OS_TYPE` | OS type info for Azure attestation | `UVC` |
| `LOG_FORWARDER_SOCKET` | Unix socket path of the log-forwarder service | `/run/cocos/log.sock` |

The backend URL can also be set via the `--backend` CLI flag.

## Deployment

```bash
# Build
make ingress-proxy

# Run (inside a CVM)
./build/cocos-ingress-proxy
```

To override the backend:

```bash
COCOS_INGRESS_BACKEND=http://localhost:7002 ./build/cocos-ingress-proxy
# or
./build/cocos-ingress-proxy --backend http://localhost:7002
```

## Example

The ingress proxy is initialized at CVM startup and waits for computation requests from the Manager. Once a computation is triggered, the Manager connects to the CVM through the proxy:

```bash
# From the host, verify aTLS by checking attestation before uploading
./build/cocos-cli attestation get '<report_data>'

# Once attestation is validated, upload the algorithm through the aTLS-secured channel
./build/cocos-cli algo ./algorithm.py private.pem --algorithm python
```
