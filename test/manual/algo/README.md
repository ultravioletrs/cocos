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

To run the examples in the confidential VM (CVM) or a regular VM by the Agent, you can use the following command:

```bash
go run ./test/cvms/main.go ./test/manual/algo/lin_reg.py public.pem false ./test/manual/data/iris.csv
```

This command is run from the root directory of the project. This will start the CVM server.

For a regular VM, in another window, run the following command:
```bash
sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
OVMF_CODE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd

# Create a local copy of OVMF_VARS.
cp /usr/share/OVMF/OVMF_VARS.fd .

OVMF_VARS=./OVMF_VARS.fd

# Create a directory for the environment file and the certificates for cloud certificates.
mkdir env
mkdir certs

# Enter the env directory and create the environemnt file.
cd env
touch environment

# Define Computations endpoint URL for agent.
# Make sure the Computation endpoint is running (like Cocos Prism).
echo AGENT_CVM_GRPC_URL=localhost:7001 >> ./environment
# Define log level for the agent.
echo AGENT_LOG_LEVEL=debug >> ./environment
cd ..

KERNEL=<path to kernel built with HAL>
INITRD=<path to initial RAM file system built with HAL>
APPEND="earlyprintk=serial console=ttyS0"
QEMU_BIN=<path to QEMU binary>
ENV_PATH=./env
CERTH_PATH=./certs

$QEMU_BIN -enable-kvm \
    -smp 4 \
    -m 8G,slots=5,maxmem=10G \
    -cpu EPYC-v4 \
    -machine q35 \
    -no-reboot \
    -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=$OVMF_VARS \
    -netdev user,id=vmnic,hostfwd=tcp::7020-:7002 \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic \
    -initrd $INITRD \
    -kernel $KERNEL -append $APPEND \
    -nographic \
    -monitor pty \
    -monitor unix:monitor,server,nowait \
    -fsdev local,id=env_fs,path=$ENV_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=env_fs,mount_tag=env_share \
    -fsdev local,id=cert_fs,path=$CERTH_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=cert_fs,mount_tag=certs_share
```

For a CVM, in another window, run the following command:

```bash
# Create a directory for the environment file and the certificates for cloud certificates.
mkdir env
mkdir certs

# Enter the env directory and create the environemnt file.
cd env
touch environment

# Define Computations endpoint URL for agent.
# Make sure the Computation endpoint is running (like Cocos Prism).
echo AGENT_CVM_GRPC_URL=localhost:7001 >> ./environment
# Define log level for the agent.
echo AGENT_LOG_LEVEL=debug >> ./environment
cd ..

KERNEL=<path to kernel built with HAL>
INITRD=<path to initial RAM file system built with HAL>
APPEND="earlyprintk=serial console=ttyS0"
IGVM=<path to IGVM file>
QEMU_BIN=<path to QEMU binary>
ENV_PATH=./env
CERTH_PATH=./certs

$QEMU_BIN -enable-kvm \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35 \
    -smp 4,maxcpus=16 \
    -m 8G,slots=5,maxmem=30G \
    -netdev user,id=vmnic,hostfwd=tcp::7020-:7002 \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
    -machine confidential-guest-support=sev0,memory-backend=ram1,igvm-cfg=igvm0 \
    -object memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false,reserve=false \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
    -object igvm-cfg,id=igvm0,file=$IGVM \
    -initrd $INITRD \
    -kernel $KERNEL -append $APPEND \
    -nographic \
    -monitor pty \
    -monitor unix:monitor,server,nowait \
    -fsdev local,id=env_fs,path=$ENV_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=env_fs,mount_tag=env_share \
    -fsdev local,id=cert_fs,path=$CERTH_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=cert_fs,mount_tag=certs_share
```

Make sure you have already built the [qemu image](../../../hal/linux/README.md) and the IGVM file from the COCONUT-SVSM [repository](https://github.com/coconut-svsm/svsm/blob/main/Documentation/docs/installation/INSTALL.md).

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
./build/cocos-cli algo ./test/manual/algo/addition.py ./private.pem -a python --args="--a" --args="100" --args="--b" --args="20"
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

Run the build command and then save the docker image as a `tar` file.

```bash
cd test/manual/algo/
docker build -t linreg .
docker save linreg > linreg.tar
```

To run the examples in the confidential VM (CVM) or a regular VM by the Agent, you can use the following command:

```bash
go run ./test/cvms/main.go ./test/manual/algo/lin_reg.py public.pem false ./test/manual/data/iris.csv
```

This command is run from the root directory of the project. This will start the CVM server.

For a regular VM, in another window, run the following command:
```bash
sudo find / -name OVMF_CODE.fd
# => /usr/share/OVMF/OVMF_CODE.fd
OVMF_CODE=/usr/share/OVMF/OVMF_CODE.fd

sudo find / -name OVMF_VARS.fd
# => /usr/share/OVMF/OVMF_VARS.fd

# Create a local copy of OVMF_VARS.
cp /usr/share/OVMF/OVMF_VARS.fd .

OVMF_VARS=./OVMF_VARS.fd

# Create a directory for the environment file and the certificates for cloud certificates.
mkdir env
mkdir certs

# Enter the env directory and create the environemnt file.
cd env
touch environment

# Define Computations endpoint URL for agent.
# Make sure the Computation endpoint is running (like Cocos Prism).
echo AGENT_CVM_GRPC_URL=localhost:7001 >> ./environment
# Define log level for the agent.
echo AGENT_LOG_LEVEL=debug >> ./environment
cd ..

KERNEL=<path to kernel built with HAL>
INITRD=<path to initial RAM file system built with HAL>
APPEND="earlyprintk=serial console=ttyS0"
QEMU_BIN=<path to QEMU binary>
ENV_PATH=./env
CERTH_PATH=./certs

$QEMU_BIN -enable-kvm \
    -smp 4 \
    -m 8G,slots=5,maxmem=10G \
    -cpu EPYC-v4 \
    -machine q35 \
    -no-reboot \
    -drive if=pflash,format=raw,unit=0,file=$OVMF_CODE,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=$OVMF_VARS \
    -netdev user,id=vmnic,hostfwd=tcp::7020-:7002 \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic \
    -initrd $INITRD \
    -kernel $KERNEL -append $APPEND \
    -nographic \
    -monitor pty \
    -monitor unix:monitor,server,nowait \
    -fsdev local,id=env_fs,path=$ENV_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=env_fs,mount_tag=env_share \
    -fsdev local,id=cert_fs,path=$CERTH_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=cert_fs,mount_tag=certs_share
```

For a CVM, in another window, run the following command:

```bash
# Create a directory for the environment file and the certificates for cloud certificates.
mkdir env
mkdir certs

# Enter the env directory and create the environemnt file.
cd env
touch environment

# Define Computations endpoint URL for agent.
# Make sure the Computation endpoint is running (like Cocos Prism).
echo AGENT_CVM_GRPC_URL=localhost:7001 >> ./environment
# Define log level for the agent.
echo AGENT_LOG_LEVEL=debug >> ./environment
cd ..

KERNEL=<path to kernel built with HAL>
INITRD=<path to initial RAM file system built with HAL>
APPEND="earlyprintk=serial console=ttyS0"
IGVM=<path to IGVM file>
QEMU_BIN=<path to QEMU binary>
ENV_PATH=./env
CERTH_PATH=./certs

$QEMU_BIN -enable-kvm \
    -enable-kvm \
    -cpu EPYC-v4 \
    -machine q35 \
    -smp 4,maxcpus=16 \
    -m 8G,slots=5,maxmem=30G \
    -netdev user,id=vmnic,hostfwd=tcp::7020-:7002 \
    -device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
    -machine confidential-guest-support=sev0,memory-backend=ram1,igvm-cfg=igvm0 \
    -object memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false,reserve=false \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
    -object igvm-cfg,id=igvm0,file=$IGVM \
    -initrd $INITRD \
    -kernel $KERNEL -append $APPEND \
    -nographic \
    -monitor pty \
    -monitor unix:monitor,server,nowait \
    -fsdev local,id=env_fs,path=$ENV_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=env_fs,mount_tag=env_share \
    -fsdev local,id=cert_fs,path=$CERTH_PATH,security_model=mapped \
    -device virtio-9p-pci,fsdev=cert_fs,mount_tag=certs_share
```

Make sure you have already built the [qemu image](../../../hal/linux/README.md) and the IGVM file from the COCONUT-SVSM [repository](https://github.com/coconut-svsm/svsm/blob/main/Documentation/docs/installation/INSTALL.md).

In another window, specify what kind of algorithm you want the Agent to run (docker):

```bash
./cocos/build/cocos-cli algo ./test/manual/algo/linreg.tar ./cocos/private.pem -a docker
```

make sure you have built the cocos-cli. This will upload the docker image.

Next we need to upload the dataset

```bash
./cocos/build/cocos-cli data ./test/manual/data/iris.csv ./cocos/private.pem
```

After some time when the results are ready, you can run the following command to get the results:

```bash
./cocos/build/cocos-cli results ./private.pem
```

This will return the results of the algorithm.

Unzip the results

```bash
unzip results.zip -d results
```

To make inference on the results, you can use the following command:

```bash
python3 ./test/manual/algo/lin_reg.py predict results/model.bin test/manual/data/
```

## Wasm Example

More information on how to run wasm files can be found [here](https://github.com/ultravioletrs/ai/tree/main/burn-algorithms).

## Binary Example

More information on how to run binary files can be found [here](https://github.com/ultravioletrs/ai/tree/main/burn-algorithms).
