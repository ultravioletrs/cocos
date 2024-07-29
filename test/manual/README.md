# Manual tests

## CLI

Throughout the tests, we assume that our current working directory is the root of the `cocos` repository, both on the host machine and in the VM.
First, we will build cli by running in the root directory of `cocos`:
```bash
make cli
```

The cli will be compiled to the build directory `./build/cocos-cli`.

### Algorithm requirements

Agent accepts the algorithm as a binary or python or wasm file.
All assets/datasets the algorithm uses are stored in the `datasets` directory. The results from the algorithm run should be stored in the `results` directory. All these paths are relative to the algorithm working directory.

### Agent-CLI interaction

Agent is started automatically in the VM when launched but requires configuration and manifest to be passed by manager. Alternatively you can pass configuration using this [simplified script](./agent-config/main.go)

For attested TLS, you will have to calculate the VM's measurement, which can be done using a tool [sev-snp-measure](https://pypi.org/project/sev-snp-measure/).

```bash
# Define the path to the OVMF, KERNEL, INITRD and CMD Kernel line arguments.
OVMF_CODE="/home/cocosai/ovmf/Build/AmdSev/DEBUG_GCC5/FV/OVMF.fd"
INITRD="/home/cocosai/initramfs.cpio.gz"
KERNEL="/home/cocosai/bzImage"
LINE="earlyprintk=serial console=ttyS0"

# Call sev-snp-measure
sev-snp-measure --mode snp --vcpus 4 --vcpu-type EPYC-v4 --ovmf $OVMF_CODE --kernel $KERNEL --initrd $INITRD --append "$LINE" --output-format base64
```

To speed up the verification process of attested TLS, download the ARK and ASK certificates using the CLI tool. The CLI tool will download the certificates under your home directory in the `.cocos` directory.
```bash
./build/cocos-cli ca-bundle <path/to/platfrom_info.json>
```

In the following text, we can see an example of how the CLI tool is used.
```bash
export AGENT_GRPC_URL=localhost:7002

# For attested TLS, the CLI needs a file containing the necessary information 
# about the SEV-SNP capable backend. This information will be used to verify 
# the attestation report received from the agent.
# The backend_info.json file can be generated using Rust by running:
cd scripts/backend_info
make
sudo ./target/release/backend_info --policy 196608 # Default value of the policy should be 196608
# The output file backend_info.json will be generated in the directory from which the executable has been called.
cd ../..

# The CLI should also be aware of the VM measurement. To add the measurement 
# to the .json file that contains the information about the platform, run CLI 
# with the measurement in base64 format and the path of the backend_info.json file.:
./build/cocos-cli backend measurement '<measurement>' '<backend_info.json>'

# If the VM is booted with the QEMU host data option, the CLI should also know 
# the host data information. To add the host data to the .json file that contains 
# the information about the platform, run CLI with the host data in base64 format 
# and the path of the backend_info.json file.:
./build/cocos-cli backend measurement '<host-data>' '<backend_info.json>'

# For attested TLS, also define the path to the backend_info.json that contains reference values for the fields of the attestation report
export AGENT_GRPC_MANIFEST=./scripts/backend_info/backend_info.json
export AGENT_GRPC_ATTESTED_TLS=true

# Retieve Attestation
./build/cocos-cli attestation get '<report_data>'

# Validate Attestation
# Product name must be Milan or Genoa
./build/cocos-cli attestation validate '<attesation>' --report_data '<report_data>' --product <product_name>

# Run the CLI program with algorithm input
./build/cocos-cli algo test/manual/algo/lin_reg.py <private_key_file_path> -a python -r test/manual/algo/requirements.py
# 2023/09/21 10:43:53 Uploading algorithm binary: test/manual/algo/lin_reg.bin

# In order to run the Docker image, run the CLI program with the algorithm docker option
go run ./cmd/cli/main.go algo -a docker -d "python3,/cocos/lin_reg.py" <path_to_docker_image.tar> <private_key_file_path>
# 2023/09/21 10:43:53 Uploading algorithm binary: <path_to_docker_image.tar>

# Run the CLI program with dataset input
./build/cocos-cli data test/manual/data/iris.csv <private_key_file_path>
# 2023/09/21 10:45:25 Uploading dataset CSV: test/manual/data/iris.csv

# Run the CLI program to fetch computation result
./build/cocos-cli result <private_key_file_path>
# 2023/09/21 10:45:39 Retrieving computation result file
# 2023/09/21 10:45:40 Computation result retrieved and saved successfully!
```

Now there is a `result.bin` file in the current working directory. The file holds the trained logistic regression model. To test the model, run

```sh
python ./test/manual/algo/lin_reg.py predict results.zip ./test/manual/data
```

You should get an output (truncated for the sake of brevity):

```sh
Precision, Recall, Confusion matrix, in training

                 precision    recall  f1-score   support

    Iris-setosa      1.000     1.000     1.000        21
Iris-versicolor      0.923     0.889     0.906        27
 Iris-virginica      0.893     0.926     0.909        27

       accuracy                          0.933        75
      macro avg      0.939     0.938     0.938        75
   weighted avg      0.934     0.933     0.933        75

[[21  0  0]
 [ 0 24  3]
 [ 0  2 25]]
Precision, Recall, Confusion matrix, in testing

                 precision    recall  f1-score   support

    Iris-setosa      1.000     1.000     1.000        29
Iris-versicolor      1.000     1.000     1.000        23
 Iris-virginica      1.000     1.000     1.000        23

       accuracy                          1.000        75
      macro avg      1.000     1.000     1.000        75
   weighted avg      1.000     1.000     1.000        75

[[29  0  0]
 [ 0 23  0]
 [ 0  0 23]]
```
