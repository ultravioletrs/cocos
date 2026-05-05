# Egress Proxy

The Egress Proxy controls outbound network traffic from inside the Confidential Virtual Machine (CVM). It acts as an HTTP CONNECT proxy, allowing the computation workload to reach only explicitly allowed external endpoints while blocking all other outbound traffic.

## Overview

Workloads running inside a CVM may need to contact external services (e.g., a model registry or a results endpoint). The egress proxy enforces an allowlist-based policy so that outbound connections are auditable and constrained. All services inside the CVM that need external access should route through this proxy.

Logs are forwarded to the log-forwarder service over a Unix socket.

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `COCOS_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`). Also accepts `AGENT_LOG_LEVEL` | `info` |
| `COCOS_PROXY_PORT` | Port the proxy listens on inside the CVM | `3128` |
| `LOG_FORWARDER_SOCKET` | Unix socket path of the log-forwarder service | `/run/cocos/log.sock` |

The port can also be set via the `--port` CLI flag.

## Deployment

```bash
# Build
make egress-proxy

# Run (inside a CVM)
./build/cocos-egress-proxy
```

To change the listening port:

```bash
COCOS_PROXY_PORT=8080 ./build/cocos-egress-proxy
# or
./build/cocos-egress-proxy --port 8080
```

## Example

Configure a workload inside the CVM to use the egress proxy:

```bash
# Set proxy for curl (or any HTTP_PROXY-aware tool)
export http_proxy=http://localhost:3128
export https_proxy=http://localhost:3128

curl https://allowed-external-endpoint.example.com/api/data
```
