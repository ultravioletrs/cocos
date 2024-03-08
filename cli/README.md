# Agent CLI

This repository contains the command-line interface (CLI) tool for interacting with the Agent and manager service. The CLI allows you to perform various tasks such as running computations, uploading algorithms and datasets, and retrieving results.

## Build

From the project root:

```bash
make cli
```

## Usage

#### Run Computation

To run a computation, use the following command:

```bash
./build/cocos-cli manager run --computation '{"name": "my-computation"}'
```

#### Get attestation
To retrieve attestation from agent, use the following command:
```bash
./build/cocos-cli agent attestation get '<report_data>'
```

#### Validate attestation
To validate and verify attestation from agent, use the following command:
```bash
./build/cocos-cli agent attestation validate '<attestation>' '<report_data>'
```

#### Upload Algorithm

To upload an algorithm, use the following command:

```bash
./build/cocos-cli agent algo /path/to/algorithm
```

#### Upload Dataset

To upload a dataset, use the following command:

```bash
./build/cocos-cli agent data /path/to/dataset.csv
```

#### Retrieve result

To retrieve the computation result, use the following command:

```bash
./build/cocos-cli agent result
```

## Installtion

To use the CLI, you have the option to install it globally on your system. Here's how:

### Build the CLI:

Navigate to the project root and run the following command to build the CLI binary:

```bash
# compile the cli
make cli

# copy binary to bin
sudo make install-cli
```
