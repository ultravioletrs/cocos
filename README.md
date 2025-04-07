<div align="center">

# Cocos AI 🥥

**Confidential Computing System for AI**

**Made with ❤️ by [Ultraviolet](https://ultraviolet.rs/)**

[![codecov](https://codecov.io/gh/ultravioletrs/cocos/graph/badge.svg?token=HX01LR01K9)](https://codecov.io/gh/ultravioletrs/cocos)
[![Go report card](https://goreportcard.com/badge/github.com/ultravioletrs/cocos)](https://goreportcard.com/report/github.com/ultravioletrs/cocos)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

### [Guide](https://docs.cocos.ultraviolet.rs) | [Contributing](CONTRIBUTING.md) | [Website](https://cocos.ai/)

</div>

## Introduction 🚀

Cocos AI is a **cutting-edge platform** designed to enable secure multiparty computation (SMPC) using **Confidential Computing** and **Trusted Execution Environments (TEEs)**.

It empowers organizations to collaboratively process sensitive data for AI/ML workloads while ensuring:

- 🔒 **Data Privacy**: Your data stays encrypted and secure throughout the computation.
- 🛡️ **Trust and Integrity**: Protected by hardware enclaves with robust remote attestation protocols.
- 🤝 **Seamless Collaboration**: Multiple organizations can work together without exposing sensitive information.

<p align="center">
  <img src="https://cocos.ai/images/Collaborative%20AI.drawio.svg" alt="Cocos AI Illustration" width="400" height="400">
</p>

## Features 🛠️

Cocos AI provides essential features for secure and efficient collaborative AI/ML:

- 🖥️ **TEE Enablement and Monitoring**: Secure VM management for deploying and monitoring workloads.
- 🛡️ **Hardware Abstraction Layer (HAL)**: Built on a hardened Linux kernel, secure bootloader, and minimal root filesystem (minimal TCB).
- 🕵️ **In-Enclave Agent and Networking Controller**: Essential system software for managing secure workloads.
- 🔒 **Encrypted Data Transfer**: Asynchronous data transfer and secure result delivery.
- 🛠️ **API for Platform Manipulation**: Programmatic control for managing workloads.
- ✅ **Attestation and Verification Tools**: Hardware- and software-supported attestation for integrity assurance.
- 🖱️ **Command-Line Interface (CLI)**: A user-friendly CLI for system interaction.

## 🚀 Quick Start

### Clone the Repository and Build Binaries
```bash
git clone git@github.com:ultravioletrs/cocos.git
make
```

This will generate three binaries:
```bash
ls build/
# cocos-agent  cocos-cli  cocos-manager
```

### Deployment Overview:
- **Manager**: Deploy on the AMD SEV-SNP host to orchestrate workloads.
- **Agent**: Build into the [EOS](https://github.com/ultravioletrs/eos)-based HAL for secure enclave management.
- **CLI**: Interact with remote agents to control operations.

## 📚 Documentation

Comprehensive documentation is available at the [official documentation page](https://docs.cocos.ultraviolet.rs).  
For CLI usage details, visit the [CLI Documentation](https://docs.cocos.ultraviolet.rs/cli).

Documentation is automatically generated from the [docs repository](https://github.com/ultravioletrs/docs). Contributions to documentation are welcome!

## 🛡️ License

Cocos AI is published under the permissive open-source [Apache-2.0](LICENSE) license. Contributions are encouraged and appreciated!
This work has been partially supported by the ELASTIC project, which received funding from the Smart Networks and Services Joint Undertaking (SNS JU) under the European Union’s Horizon Europe research and innovation programme under Grant Agreement No 101139067. Views and opinions expressed are however those of the author(s) only and do not necessarily reflect those of the European Union. Neither the European Union nor the granting authority can be held responsible for them.

## 🌐 Links and Resources

- [Cocos AI Website](https://cocos.ai/)
- [Official Releases](https://github.com/ultravioletrs/cocos/releases)
- [Confidential Computing Overview](https://confidentialcomputing.io/white-papers-reports/)
- [Trusted Execution Environments (TEEs)](https://en.wikipedia.org/wiki/Trusted_execution_environment)
