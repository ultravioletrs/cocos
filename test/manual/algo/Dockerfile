FROM python:3.9-slim

# set the working directory in the container
WORKDIR /cocos
RUN mkdir /cocos/results
RUN mkdir /cocos/datasets

COPY ./requirements.txt /cocos/requirements.txt
COPY ./lin_reg.py /cocos/lin_reg.py

# install dependencies
RUN pip install -r requirements.txt

# command to be run when the docker container is started
CMD ["python3", "-u", "/cocos/lin_reg.py"]
