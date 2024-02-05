# Manual tests

## CLI

Throughout the tests, we assume that our current working directory is the root of the `agent` repository, both on the host machine and in the VM.

### Python requirements

Do this both on the host machine and in the VM.

```sh
apt update
apt install python3-pip
pip3 install pandas scikit-learn
```

### Agent-CLI interaction

Agent is started automatically in the VM when launched but requires configuration and manifest to be passed by manager. Alternatively you can pass configuration using this [simplified script](./agent-config/main.go)

Open console on the host, and run

```sh
export AGENT_GRPC_URL=localhost:7002
export MANAGER_GRPC_URL=localhost:7001

# Run CLI to provide manifest
go run cmd/cli/main.go run '{"id":"123","name":"Sample Computation","description":"A sample computation","status":"Processing","owner":"John Doe","start_time":"2023-11-03T12:03:21.705171284+03:00","end_time":"2023-11-03T13:03:21.705171532+03:00","datasets":[{"provider":"Provider1","id":"Dataset1"},{"provider":"Provider2","id":"Dataset2"}],"algorithms":[{"provider":"AlgorithmProvider1","id":"Algorithm1"}],"result_consumers":["Consumer1","Consumer2"],"ttl":3600,"metadata":{"key1":"value1","key2":42}, "timeout": "2m"}'

# Retieve Attestation
go run cmd/cli/main.go agent attestation get '<report_data>'

# Validate Attestation
go run cmd/cli/main.go agent attestation validate '<attesation>' '<report_data>'

# Run the CLI program with algorithm input
go run cmd/cli/main.go agent algo test/manual/algo/lin_reg.py Algorithm1 AlgorithmProvider1
# 2023/09/21 10:43:53 Uploading algorithm binary: test/manual/algo/lin_reg.py

# Run the CLI program with dataset input
go run cmd/cli/main.go agent data test/manual/data/iris.csv Dataset1 Provider1
go run cmd/cli/main.go agent data test/manual/data/iris.csv Dataset2 Provider2
# 2023/09/21 10:45:25 Uploading dataset CSV: test/manual/data/iris.csv

# Run the CLI program to fetch computation result
go run cmd/cli/main.go agent result Consumer1
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
