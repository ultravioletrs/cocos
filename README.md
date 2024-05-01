# Cocos AI
[Cocos AI (Confdential Computing System for AI/ML)][cocos] is a platform for secure multiparty computation (SMPC)
based on the [Confidential Computing][cc] and [Trusted Execution Environments (TEEs)][tee].

<p align="center">
  <img src="https://cocos.ai/images/Collaborative%20AI.drawio.svg" width="500" height="500">
</p>

With Cocos AI it becomes possible to run AI/ML workloads on combined datasets from multiple organizations
while guaranteeing the privacy and security of the data and the algorithm.
Data is always encrypted, protected by hardware secure enclaves (Trusted Execution Environments),
attested via secure remote attestation protocols, and invisible to cloud processors or any other
3rd party to which computation is offloaded.

## Features

Cocos AI is implementing the following features:

- TEE enablement, deployment and monitoring (secure VM manager)
- HAL for TEEs based on hardened Linux kernel, secure bootloader and custom-tailored embedded rootfs for minimal TCB
- In-enclave agent, netowrking controller and other system software
- Encrypted asynchronous data transfer and result delivery
- API for programmable platform manipulation
- HW and SW supported attestation with verification tools
- CLI for system interaction

## Usage

Clone the repo and create binaries:

```bash
git clone git@github.com:ultravioletrs/cocos.git
make
```

This will create 3 binaries:
```bash
ls build/
# cocos-agent  cocos-cli  cocos-manager
```

- Manager can be deployed on the AMD SEV-SNP host
- Agent can be built into [EOS][eos]-based HAL
- CLI can be used to communicate to remote Agent.

## Documentation

Project documentation is hosted at [Cocos AI official docs page][docs].

Documentation is generated from the [docs repository](https://github.com/ultravioletrs/docs).

## License
Cocos AI is published under permissive open-source [Apache-2.0](LICENSE) license.

[cc]: https://confidentialcomputing.io/white-papers-reports/
[cocos]: https://cocos.ai/
[rel]: https://github.com/ultravioletrs/cocos/releases
[tee]: https://en.wikipedia.org/wiki/Trusted_execution_environment
[docs]: https://docs.cocos.ultraviolet.rs
[cli]: https://docs.cocos.ultraviolet.rs/cli
[eos]: https://github.com/ultravioletrs/eos
