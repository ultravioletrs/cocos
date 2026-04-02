# Log Forwarder

The Log Forwarder collects structured log entries from all in-CVM services (Agent, attestation-service, computation-runner, egress-proxy, ingress-proxy) and streams them to the Manager over the existing gRPC CVM stream. This allows operators to observe computation events and service logs from outside the CVM without requiring a separate network channel.

## Overview

In-CVM services write log entries to the Log Forwarder's Unix socket at `/run/cocos/log.sock`. The forwarder batches these entries and forwards them to the Manager via the `AGENT_CVM_GRPC_*` channel that was established when the CVM was launched. The Manager then surfaces these logs through its own event stream to the caller (e.g., the CLI).

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `LOG_FORWARDER_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`). Also accepts `AGENT_LOG_LEVEL` | `debug` |

The connection to the Manager is configured via the standard `AGENT_CVM_GRPC_*` environment variables (read at startup from the 9P-shared environment file):

| Variable | Description | Default |
| --- | --- | --- |
| `AGENT_CVM_GRPC_HOST` | Manager gRPC host | `""` |
| `AGENT_CVM_GRPC_PORT` | Manager gRPC port | `7001` |
| `AGENT_CVM_GRPC_SERVER_CERT` | Path to Manager gRPC server certificate (PEM) | `""` |
| `AGENT_CVM_GRPC_SERVER_KEY` | Path to Manager gRPC server key (PEM) | `""` |
| `AGENT_CVM_GRPC_SERVER_CA_CERTS` | Path to Manager gRPC CA certificate | `""` |
| `AGENT_CVM_GRPC_CLIENT_CA_CERTS` | Path to Manager gRPC client CA certificate | `""` |

## Deployment

```bash
# Build
make log-forwarder

# Run (inside a CVM — normally started automatically at boot)
./build/cocos-log-forwarder
```

The service listens on `/run/cocos/log.sock` and creates the `/run/cocos/` directory if needed. It is typically started before all other in-CVM services so they can connect to it immediately.

## Example

From the Manager side, logs from inside the CVM appear in the computation event stream. Using the CLI:

```bash
# The CLI receives streamed events including in-CVM log lines
./build/cocos-cli algo ./algorithm.py private.pem --algorithm python
# Console output will include forwarded in-CVM logs:
# [computation-runner] Starting Python computation...
# [computation-runner] Loading dataset from /run/cocos/datasets/...
# [computation-runner] Computation completed successfully
```
