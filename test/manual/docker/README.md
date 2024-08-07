# Manual tests - Docker

Throughout the test, we assume that our current working directory is the directory in which the `cocos` repository is cloned. For example:
```bash
ls
cocos  Dockerfile
```
The docker image that the Agent will run inside the SVM must have the following directories:
* `/datasets` directory where the Agent will mount the datasets.
* `/results` directory from which the Agent will fetch the results.

As you can see, the directory structure that the docker image must follow is the same as if the algorithm were run inside the VM using any other method of execution.

## Logistic Regression example

Here we will use the docker with the `lin_reg.py` algorithm.

The first step is to create a docker file containing the algorithm. Use your favorite editor to create a file named `Dockerfile`.

```bash
FROM python:3.9-slim

# set the working directory in the container
WORKDIR /cocos
RUN mkdir /results
RUN mkdir /datasets 

COPY ./cocos/test/manual/algo/requirements.txt /cocos/requirements.txt
COPY ./cocos/test/manual/algo/lin_reg.py /cocos/lin_reg.py

# install dependencies
RUN pip install -r requirements.txt
```

Next, run the build command and then save the docker image as a `tar` file.
```bash
docker build -t linreg .
docker save linreg > linreg.tar
```

After the VM starts (you can find more about the VM booting process in the manual testing README file), use the CLI to send the docker image to the Agent. To run the Docker inside the VM, specify what kind of algorithm you want the Agent to run and the Docker run command.

```bash
go run ./cocos/cmd/cli/main.go algo -a docker -d "python3 /cocos/lin_reg.py" ./linreg.tar <private_key_file_path>
```
