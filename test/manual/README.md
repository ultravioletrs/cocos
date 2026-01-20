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

Agent is started automatically in the VM when launched but requires configuration and manifest to be passed by manager. Alternatively you can pass configuration using this [simplified script](/test/cvms/main.go)

For attested TLS, you will have to calculate the VM's measurement, which can be done using cli. This information is also contained in the Attestation Policy file.

```bash
# Define the path to the IGVM file that contains the vTPM and the OVMF.
IGVM="<path to the IGVM file>" 

# Call igvmmeasure
./build/cocos-cli igvmmeasure $IGVM
```

To speed up the verification process of attested TLS, download the ARK and ASK certificates using the CLI tool. The CLI tool will download the certificates under your home directory in the `.cocos` directory.
```bash
./build/cocos-cli ca-bundle <path/to/attestation_policy.json>
```

In the following text, we can see an example of how the CLI tool is used.
```bash
export AGENT_GRPC_URL=localhost:7002

# For attested TLS, the CLI needs a file containing the necessary information 
# about the SEV-SNP capable backend. This information will be used to verify 
# the attestation report received from the agent.
# The attestation_policy.json file can be generated using Rust by running:
cd scripts/attestation_policy
make
sudo ./target/release/attestation_policy --policy 196608 # Default value of the policy should be 196608

# In order to include the golden (good) PCR values in the attestation policy, call the attestation policy script with the "--pcr" option.
sudo ./target/release/attestation_policy --policy 196608 --pcr ./pcr_values.json

# The output file attestation_policy.json will be generated in the directory from which the executable has been called.
cd ../..

# The CLI should also be aware of the VM measurement. To add the measurement 
# to the .json file that contains the information about the platform, run CLI 
# with the measurement in base64 format and the path of the attestation_policy.json file.:
./build/cocos-cli policy measurement '<measurement>' '<attestation_policy.json>'

# If the VM is booted with the QEMU host data option, the CLI should also know 
# the host data information. To add the host data to the .json file that contains 
# the information about the platform, run CLI with the host data in base64 format 
# and the path of the attestation_policy.json file.:
./build/cocos-cli policy hostdata '<host-data>' '<attestation_policy.json>'

# For attested TLS, also define the path to the attestation_policy.json that contains reference values for the fields of the attestation report
export AGENT_GRPC_ATTESTATION_POLICY=./scripts/attestation_policy/attestation_policy.json
export AGENT_GRPC_ATTESTED_TLS=true

# Retrieve Attestation
# Three different attestation reports can be retrieved:
#  - SEV-SNP with argument snp for attestation get command.
./build/cocos-cli attestation get snp --tee '<report_data>'

#  - vTPM with argument vtpm for attestation get command.
./build/cocos-cli attestation get vtpm --vtpm '<vtpm_nonce>'

#  - vTPM with SEV-SNP with argument snp-vtpm for attestation get command.
./build/cocos-cli attestation get snp-vtpm --tee '<report_data>' --vtpm '<vtpm_nonce>'

# Validate Attestation
# Product name must be Milan or Genoa
./build/cocos-cli attestation validate '<attesation>' --report_data '<report_data>' --product <product_name>

# Other options for attestation validation using the CLI are:
# validate <attestationreportfilepath> --report_data <reportdata> --product <product data> //default
# validate --mode snp <attestationreportfilepath> --report_data <reportdata> --product <product data>
# validate --mode vtpm <attestationreportfilepath> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>
# validate --mode snp-vtpm <attestationreportfilepath> --nonce <noncevalue> --format <formatvalue>  --output <outputvalue>

# Run the CLI program with algorithm input
./build/cocos-cli algo test/manual/algo/lin_reg.py <private_key_file_path> -a python -r test/manual/algo/requirements.py
# 2023/09/21 10:43:53 Uploading algorithm binary: test/manual/algo/lin_reg.bin

# In order to run the Docker image, run the CLI program with the algorithm docker option
go run ./cmd/cli/main.go algo -a docker <path_to_docker_image.tar> <private_key_file_path>
# 2023/09/21 10:43:53 Uploading algorithm binary: <path_to_docker_image.tar>

# Run the CLI program with dataset input
./build/cocos-cli data test/manual/data/iris.csv <private_key_file_path>
# 2023/09/21 10:45:25 Uploading dataset CSV: test/manual/data/iris.csv

# Run the CLI program to fetch computation result
./build/cocos-cli result <private_key_file_path>
# 2023/09/21 10:45:39 Retrieving computation result file
# 2023/09/21 10:45:40 Computation result retrieved and saved successfully!
```

Now there is a `result.zip` file in the current working directory. The file holds the trained logistic regression model. To test the model, run

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
