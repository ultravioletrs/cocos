# Cocos AI
[Cocos AI (Confdential Computing System for AI/ML)][cocos] is a platform for secure multiparty computation (SMPC)
based on the [Confidential Computing][cc] and [Trusted Execution Environments (TEEs)][tee].

<p align="center">
  <img src="https://cocos.ai/images/Collaborative%20AI.drawio.svg" width="500" height="500">
</p>

With Cocos AI it becomes possible to run AI/ML workloads on combined datasets from multiple organizations
while guaranteeing the privacy and security of the data and the algorithms.
Data is always encrypted, protected by hardware secure enclaves (Trusted Execution Environments),
attested via secure remote attestation protocols, and invisible to cloud processors or any other
3rd party to which computation is offloaded.

## Install
The following prerequisites are needed to run Cocos:

- [Docker](https://docs.docker.com/install/)
- [Docker compose](https://docs.docker.com/compose/install/)

Once the prerequisites are installed, execute the following commands from the project's root:

```bash
docker-compose -f docker/docker-compose.yml up
```

This will bring up the Cocos docker services and interconnect them. This command can also be executed using the project's included Makefile:

```bash
make run
```

If you want to run services from specific release checkout code from github and make sure that
`COCOS_RELEASE_TAG` in [.env](.env) is being set to match the release version

```bash
git checkout tags/<release_number> -b <release_number>
# e.g. `git checkout tags/0.13.0 -b 0.13.0`
```

Check that `.env` file contains:

```bash
COCOS_RELEASE_TAG=<release_number>
```

>`docker-compose` should be used for development and testing deployments. For production Kubernetes will be used.

## Usage

The quickest way to start using Cocos is via the CLI. The latest version can be downloaded from the [official releases page][rel].

It can also be built and used from the project's root directory:

```bash
make cli
./build/cocos-cli version
```

Additional details on using the CLI can be found in the [CLI documentation](https://docs.mainflux.io/cli).

## Documentation

Official documentation is hosted at [Cocos official docs page][docs]. Documentation is auto-generated, checkout the instructions on [official docs repository](https://github.com/cocos/docs).

## License
Cocos AI is a proprietary product created by Ultraviolet company.

[cc]: https://confidentialcomputing.io/white-papers-reports/
[cocos]: https://cocos.ai/
[rel]: https://github.com/ultraviolet/cocos/releases
[tee]: https://en.wikipedia.org/wiki/Trusted_execution_environment
