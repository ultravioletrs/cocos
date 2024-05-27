# Manual tests

## CLI

Throughout the tests, we assume that our current working directory is the root of the `cocos` repository, both on the host machine and in the VM.

### Algorithm requirements

Agent accepts the algorithm as a binary that take in two command line arguments.
```shell
algorithm-file <unix socket path> <dataset file paths> 
```

The algorithm program should return the results to a socket and an example can be seen in this [file](./algo/lin_reg.py).

### Agent-CLI interaction

Agent is started automatically in the VM when launched but requires configuration and manifest to be passed by manager. Alternatively you can pass configuration using this [simplified script](./agent-config/main.go)

Open console on the host, and run

```sh
export AGENT_GRPC_URL=localhost:7002

# For attested TLS, also define the path to the computation.json that contains reference values for the fields of the attestation report
export AGENT_GRPC_MANIFEST=./test/manual/computation/computation.json
export AGENT_GRPC_ATTESTED_TLS=true

# Retieve Attestation
go run cmd/cli/main.go attestation get '<report_data>'

# Validate Attestation
go run cmd/cli/main.go attestation validate '<attesation>' --report_data '<report_data>'

# Run the CLI program with algorithm input
go run cmd/cli/main.go algo test/manual/algo/lin_reg.bin <private_key_file_path>
# 2023/09/21 10:43:53 Uploading algorithm binary: test/manual/algo/lin_reg.bin

# Run the CLI program with dataset input
go run cmd/cli/main.go data test/manual/data/iris.csv <private_key_file_path>
go run cmd/cli/main.go data test/manual/data/iris.csv <private_key_file_path>
# 2023/09/21 10:45:25 Uploading dataset CSV: test/manual/data/iris.csv

# Run the CLI program to fetch computation result
go run cmd/cli/main.go result <private_key_file_path>
# 2023/09/21 10:45:39 Retrieving computation result file
# 2023/09/21 10:45:40 Computation result retrieved and saved successfully!
```

Now there is a `result.bin` file in the current working directory. The file holds the trained logistic regression model. To test the model, run

```sh
python3 test/manual/algo/lin_reg_test.py test/manual/data/iris.csv result.bin
```

You should get an output (truncated for the sake of brevity):

```sh
   Id  SepalLengthCm  SepalWidthCm  PetalLengthCm  PetalWidthCm      Species
0   1            5.1           3.5            1.4           0.2  Iris-setosa
1   2            4.9           3.0            1.4           0.2  Iris-setosa
2   3            4.7           3.2            1.3           0.2  Iris-setosa
3   4            4.6           3.1            1.5           0.2  Iris-setosa
4   5            5.0           3.6            1.4           0.2  Iris-setosa
Precision, Recall, Confusion matrix, in training

                 precision    recall  f1-score   support

    Iris-setosa      1.000     1.000     1.000        21
Iris-versicolor      0.923     0.889     0.906        27
 Iris-virginica      0.893     0.926     0.909        27

       accuracy                          0.933        75
      macro avg      0.939     0.938     0.938        75
   weighted avg      0.934     0.933     0.933        75
```
