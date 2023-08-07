# Agent CLI

This repository contains the command-line interface (CLI) tool for interacting with the Agent service. The CLI allows you to perform various tasks such as running computations, uploading algorithms and datasets, and retrieving results.

## Build

From the project root:

```bash
make cocos-cli
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

If you want to install the CLI globally, you can use the following command:

```bash
sudo cp build/agent-cli /usr/local/bin/
```

This will make the agent-cli executable available from any location in your terminal.
