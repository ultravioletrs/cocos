<div align="center">

# Cocos AI

**Confidential Computing System for AI**

Made with ❤️ by [Ultraviolet](https://ultraviolet.rs/)

[![CI](https://github.com/ultravioletrs/cocos/actions/workflows/main.yaml/badge.svg)](https://github.com/ultravioletrs/cocos/actions/workflows/main.yaml)
[![codecov](https://codecov.io/gh/ultravioletrs/cocos/graph/badge.svg?token=HX01LR01K9)](https://codecov.io/gh/ultravioletrs/cocos)
[![Go Report Card](https://goreportcard.com/badge/github.com/ultravioletrs/cocos)](https://goreportcard.com/report/github.com/ultravioletrs/cocos)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[Documentation](https://docs.cocos.ultraviolet.rs) | [Contributing](CONTRIBUTING.md) | [Website](https://cocos.ai/)

</div>

## Overview

Cocos AI is a platform for secure multiparty computation (SMPC) using **Confidential Computing** and **Trusted Execution Environments (TEEs)**. It enables organizations to collaboratively run AI/ML workloads on sensitive data while cryptographically guaranteeing that data remains private and computation results are trustworthy.

<p align="center">
  <img src="https://cocos.ai/images/Collaborative%20AI.drawio.svg" alt="Cocos AI Architecture" width="500">
</p>

## Features

- 🖥️ **TEE Enablement and Monitoring** — Deploy and monitor workloads inside AMD SEV-SNP and Intel TDX enclaves
- 🛡️ **Hardware Abstraction Layer (HAL)** — Hardened Linux kernel, secure bootloader, and minimal root filesystem (minimal TCB)
- 🕵️ **In-Enclave Agent** — System software managing secure workloads and networking inside the CVM
- 🔒 **Encrypted Data Transfer** — Asynchronous upload and result delivery with end-to-end encryption
- ✅ **Remote Attestation** — Hardware- and software-backed attestation with SEV-SNP, TDX, vTPM, and Azure MAA support
- 🤝 **Multi-Party Computation** — Multiple data owners can contribute without exposing raw data to each other or the operator
- 🛠️ **Programmatic API** — gRPC and HTTP APIs for full workload lifecycle management
- 🖱️ **CLI** — Command-line interface for attestation, algorithm/dataset upload, and result retrieval
- 📦 **OCI Support** — Run container workloads as confidential computations
- 📡 **Proxy Networking** — Ingress and egress proxy services with allowlist-based network control
- 📊 **Observability** — OpenTelemetry tracing (Jaeger), structured logging, and Prometheus/Grafana monitoring

## Architecture

Cocos consists of three primary binaries and five supporting services:

| Component | Role | Default Port | README |
| --- | --- | --- | --- |
| `cocos-manager` | Orchestrates VM lifecycle on the TEE host; accepts workload requests | gRPC `7001`, HTTP `7003` | [manager/README.md](manager/README.md) |
| `cocos-agent` | Runs inside the CVM; accepts algorithm/dataset uploads and executes computations | gRPC `7002` | [agent/README.md](agent/README.md) |
| `cocos-cli` | Client tool for operators and data owners | — | [cli/README.md](cli/README.md) |
| `attestation-service` | Retrieves and wraps hardware attestation reports (SEV-SNP, TDX, vTPM) | Unix socket `/run/cocos/attestation.sock` | [cmd/attestation-service/README.md](cmd/attestation-service/README.md) |
| `computation-runner` | Executes computation payloads (binary, Python, WASM, Docker) | Unix socket `/run/cocos/runner.sock` | [cmd/computation-runner/README.md](cmd/computation-runner/README.md) |
| `egress-proxy` | Controls outbound network access from inside the CVM | `3128` | [cmd/egress-proxy/README.md](cmd/egress-proxy/README.md) |
| `ingress-proxy` | Controls inbound network access into the CVM with aTLS | — | [cmd/ingress-proxy/README.md](cmd/ingress-proxy/README.md) |
| `log-forwarder` | Collects logs from in-CVM services and forwards them to the Manager | Unix socket `/run/cocos/log.sock` | [cmd/log-forwarder/README.md](cmd/log-forwarder/README.md) |

The HAL provides the in-enclave OS:

| Component | Role | README |
| --- | --- | --- |
| HAL Linux | Buildroot-based custom in-enclave Linux distribution | [hal/linux/README.md](hal/linux/README.md) |
| HAL Cloud | Cloud-init setup for Ubuntu-based agent deployment | [hal/cloud/README.md](hal/cloud/README.md) |

## Quick Start

### Prerequisites

- Go 1.22+
- Linux x86-64 host
- For hardware TEE: AMD EPYC processor with SEV-SNP support **or** Intel TDX-capable CPU
- QEMU-KVM (for Manager): `sudo apt install qemu-kvm`

### Build

```bash
git clone git@github.com:ultravioletrs/cocos.git
cd cocos
make
```

This produces three binaries in `build/`:

```text
build/
├── cocos-agent      # In-enclave agent
├── cocos-cli        # CLI tool
└── cocos-manager    # Host-side workload orchestrator
```

To build individual components:

```bash
make manager
make agent
make cli
```

### Deployment Overview

**Manager** runs on the AMD SEV-SNP or Intel TDX host and manages VM lifecycle:

```bash
# Basic start (KVM, no hardware TEE)
./build/cocos-manager

# AMD SEV-SNP
MANAGER_QEMU_ENABLE_SEV_SNP=true \
MANAGER_QEMU_IGVM_FILE=/etc/cocos/coconut-qemu.igvm \
MANAGER_QEMU_BIN_PATH=/usr/bin/qemu-system-x86_64 \
./build/cocos-manager

# Intel TDX
MANAGER_QEMU_ENABLE_TDX=true \
MANAGER_QEMU_CPU=host \
MANAGER_QEMU_OVMF_FILE=/path/to/OVMF.fd \
MANAGER_QEMU_BIN_PATH=/usr/bin/qemu-system-x86_64 \
./build/cocos-manager
```

**Agent** is built into the [EOS](https://github.com/ultravioletrs/eos)-based HAL and starts automatically inside the CVM.

**CLI** connects to a running Agent or Manager:

```bash
# Upload an algorithm and retrieve the result
./build/cocos-cli algo /path/to/algorithm private_key.pem
./build/cocos-cli result private_key.pem
```

## Documentation

Full documentation is available at [docs.cocos.ultraviolet.rs](https://docs.cocos.ultraviolet.rs).

- [CLI Reference](https://docs.cocos.ultraviolet.rs/cli)
- [Documentation source](https://github.com/ultravioletrs/docs)

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

Cocos AI is published under the [Apache-2.0](LICENSE) license.

## Acknowledgements

> This work has been partially supported by the [ELASTIC](https://elasticproject.eu/) and [CONFIDENTIAL6G](https://confidential6g.eu/) projects, which received funding from the Smart Networks and Services Joint Undertaking (SNS JU) under the European Union's Horizon Europe research and innovation programme under [Grant Agreement No. 101139067](https://cordis.europa.eu/project/id/101139067) and [Grant Agreement No. 101096435](https://cordis.europa.eu/project/id/101096435). Views and opinions expressed are those of the author(s) only and do not necessarily reflect those of the European Union or the granting authority.
