# Algorithm

Agent accepts binaries programs, python scripts, Docker images and wasm files. It runs them in a sandboxed environment and returns the output.

## Python Example

To test this examples work on your local machine, you need to install the following dependencies:

```bash
pip install -r requirements.txt
```

This can be done in a virtual environment.

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

To run the example, you can use the following command:

```bash
python3 test/manual/algo/addition.py
```

The addition example is a simple algorithm to demonstrate you can run an algorithm without any external dependencies and input arguments. It returns the sum of two numbers.

```bash
python3 test/manual/algo/lin_reg.py
```

The linear regression example is a more complex algorithm that requires external dependencies.It returns a linear regression model trained on the iris dataset found [here](../data/) for demonstration purposes.

```bash
python3 test/manual/algo/lin_reg.py predict results.zip  test/manual/data
```

This will make inference on the results of the linear regression model.

To run the examples in the secure VM (SVM) by the Agent, you can use the following command:

```bash
go run ./test/computations/main.go ./test/manual/algo/lin_reg.py public.pem false ./test/manual/data/iris.csv
```

This command is run from the root directory of the project. This will start the computation server.

In another window, you can run the following command:

```bash
sudo MANAGER_QEMU_SMP_MAXCPUS=4 MANAGER_GRPC_URL=localhost:7001 MANAGER_LOG_LEVEL=debug MANAGER_QEMU_USE_SUDO=false  MANAGER_QEMU_ENABLE_SEV=false MANAGER_QEMU_SEV_CBITPOS=51 MANAGER_QEMU_ENABLE_SEV_SNP=false MANAGER_QEMU_OVMF_CODE_FILE=/usr/share/edk2/x64/OVMF_CODE.fd MANAGER_QEMU_OVMF_VARS_FILE=/usr/share/edk2/x64/OVMF_VARS.fd go run main.go
```

This command is run from the [manager main directory](../../../cmd/manager/). This will start the manager. Make sure you have already built the [qemu image](../../../hal/linux/README.md).

In another window, you can run the following command:

```bash
./build/cocos-cli algo ./test/manual/algo/lin_reg.py ./private.pem -a python -r ./test/manual/algo/requirements.txt
```

make sure you have built the cocos-cli. This will upload the algorithm and the requirements file.

Next we need to upload the dataset

```bash
./build/cocos-cli data ./test/manual/data/iris.csv ./private.pem
```

After some time when the results are ready, you can run the following command to get the results:

```bash
./build/cocos-cli result ./private.pem
```

This will return the results of the algorithm.

To make inference on the results, you can use the following command:

```bash
python3 test/manual/algo/lin_reg.py predict results.zip  test/manual/data
```

For addition example, you can use the following command:

```bash
./build/cocos-cli ./test/manual/algo/addition.py public.pem false
```

```bash
./build/cocos-cli algo ./test/manual/algo/addition.py ./private.pem -a python --args="--a,100,--b,20"
```

```bash
./build/cocos-cli result ./private.pem
```

## Docker Example

Here we will use the docker with the linear regression example (`lin_reg.py`). Throughout the example, we assume that our current working directory is the directory in which the `cocos` repository is cloned. For example:
```bash
# ls
cocos
```

The docker image must have a `cocos` directory containing the `datasets` and `results` directories. The Agent will run this image inside the SVM and will mount the datasets and results onto the `/cocos/datasets` and `/cocos/results` directories inside the image. The docker image must also contain the command that will be run when the docker container is run.

The first step is to create a docker file. Use your favorite editor to create a file named `Dockerfile` in the current working directory and write in it the following code:

```bash
FROM python:3.9-slim

# set the working directory in the container
WORKDIR /cocos
RUN mkdir /cocos/results
RUN mkdir /cocos/datasets 

COPY ./cocos/test/manual/algo/requirements.txt /cocos/requirements.txt
COPY ./cocos/test/manual/algo/lin_reg.py /cocos/lin_reg.py

# install dependencies
RUN pip install -r requirements.txt

# command to be run when the docker container is started
CMD ["python3", "/cocos/lin_reg.py"]
```

Next, run the build command and then save the docker image as a `tar` file.
```bash
docker build -t linreg .
docker save linreg > linreg.tar
```

In another window, you can run the following command:

```bash
sudo MANAGER_QEMU_SMP_MAXCPUS=4 MANAGER_GRPC_URL=localhost:7001 MANAGER_LOG_LEVEL=debug MANAGER_QEMU_USE_SUDO=false  MANAGER_QEMU_ENABLE_SEV=false MANAGER_QEMU_SEV_CBITPOS=51 MANAGER_QEMU_ENABLE_SEV_SNP=false MANAGER_QEMU_OVMF_CODE_FILE=/usr/share/edk2/x64/OVMF_CODE.fd MANAGER_QEMU_OVMF_VARS_FILE=/usr/share/edk2/x64/OVMF_VARS.fd go run main.go
```

This command is run from the [manager main directory](../../../cmd/manager/). This will start the manager. Make sure you have already built the [qemu image](../../../hal/linux/README.md).

In another window, specify what kind of algorithm you want the Agent to run (docker):

```bash
./cocos/build/cocos-cli algo ./linreg.tar ./cocos/private.pem -a docker
```

make sure you have built the cocos-cli. This will upload the docker image.

Next we need to upload the dataset

```bash
./cocos/build/cocos-cli data ./cocos/test/manual/data/iris.csv ./cocos/private.pem
```

After some time when the results are ready, you can run the following command to get the results:

```bash
./cocos/build/cocos-cli results ./cocos/private.pem
```

This will return the results of the algorithm.

To make inference on the results, you can use the following command:

```bash
python3 ./cocos/test/manual/algo/lin_reg.py predict result.zip ./cocos/test/manual/data
```

## Wasm Example

More information on how to run wasm files can be found [here](https://github.com/ultravioletrs/ai/tree/main/burn-algorithms).

## Binary Example

More information on how to run binary files can be found [here](https://github.com/ultravioletrs/ai/tree/main/burn-algorithms).
