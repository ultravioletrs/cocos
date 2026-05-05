# Computation Runner

The Computation Runner executes workload payloads inside the Confidential Virtual Machine (CVM). It is started by the Agent when a computation is triggered and communicates with it over a Unix domain socket.

## Overview

The runner supports multiple workload types:

- **Binary** (`bin`) — native Linux executable
- **Python** — script executed with a configurable Python runtime
- **WebAssembly** (`wasm`) — executed with [Wasmtime](https://wasmtime.dev/)
- **Docker** — container image run inside the CVM

The runner receives the algorithm and dataset paths from the Agent, executes the workload in isolation, and streams logs and events back. On completion, the result is placed in a location accessible to the Agent for encrypted retrieval.

The socket path is `/run/cocos/runner.sock` (fixed at compile time).

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `RUNNER_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`). Also accepts `AGENT_LOG_LEVEL` | `debug` |
| `LOG_FORWARDER_SOCKET` | Unix socket path of the log-forwarder service | `/run/cocos/log.sock` |

## Deployment

```bash
# Build
make computation-runner

# Run (inside a CVM — normally started automatically by the Agent)
./build/cocos-computation-runner
```

The runner listens on `/run/cocos/runner.sock`. It is typically not started manually — the Agent spawns it when a computation is received.

## Example

When the Agent receives an `Algo` + `Data` upload and a run trigger, it invokes the runner. From the host side, the full flow uses the CLI:

```bash
# Upload algorithm (Python example)
./build/cocos-cli algo ./model_training.py private.pem \
  --algorithm python \
  --requirements ./requirements.txt

# Upload dataset
./build/cocos-cli data ./training_data.csv private.pem

# The Agent automatically delegates execution to the computation-runner.
# Retrieve the result once computation is complete:
./build/cocos-cli result private.pem
```
