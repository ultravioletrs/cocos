# Agent CLI

This repository contains the command-line interface (CLI) tool for interacting with the Agent service. The CLI allows you to perform various tasks such as running computations, uploading algorithms and datasets, and retrieving results.

## Build

From the project root:

```bash
make cli
```

## Usage

#### Run Computation

To run a computation, use the following command:

```bash
./build/cocos-cli run --computation '{"name": "my-computation"}'
```

#### Upload Algorithm

To upload an algorithm, use the following command:

```bash
./build/cocos-cli algo /path/to/algorithm
```

#### Upload Dataset

To upload a dataset, use the following command:

```bash
./build/cocos-cli data /path/to/dataset.csv
```

#### Retrieve result

To retrieve the computation result, use the following command:

```bash
./build/cocos-cli result
```

## Installtion

To use the CLI, you have the option to install it globally on your system. Here's how:

### Build the CLI:

Navigate to the project root and run the following command to build the CLI binary:

```bash
make install-cli
```
