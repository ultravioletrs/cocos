# Manual tests - Docker

Throughout the test, we assume that our current working directory is the directory in which the `cocos` repository is cloned. For example:
```bash
ls
cocos  Dockerfile
```
The docker image must have a `cocos` directory containing the `datasets` and `results` directories. The Agent will run this image inside the SVM and will mount the datasets and results onto the `/cocos/datasets` and `/cocos/results` directories inside the image. The docker image must also contain the command that will be run when the docker container is run.

## Logistic Regression example

Here we will use the docker with the `lin_reg.py` algorithm.

The first step is to create a docker file. Use your favorite editor to create a file named `Dockerfile`.

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

After the VM starts (you can find more about the VM booting process in the manual testing README file), use the CLI to send the docker image to the Agent. To run the Docker inside the VM, specify what kind of algorithm you want the Agent to run (docker) and the absolut path to the datasets and results directories.

```bash
go run ./cocos/cmd/cli/main.go algo ./linreg.tar <private_key_file_path> -a docker
```
