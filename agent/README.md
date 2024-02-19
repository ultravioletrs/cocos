# Agent

Agent service provides a barebones gRPC API and Service interface implementation for the development of the agent service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable                   | Description                                            | Default |
| -------------------------- | ------------------------------------------------------ | ------- |
| AGENT_LOG_LEVEL            | Log level for agent service (debug, info, warn, error) | info    |
| AGENT_GRPC_SERVER_CERT     | Path to gRPC server certificate in pem format          | ""      |
| AGENT_GRPC_SERVER_KEY      | Path to gRPC server key in pem format                  | ""      |
| AGENT_GRPC_SERVER_CA_CERTS | Path to gRPC server CA certificate                     | ""      |
| AGENT_GRPC_CLIENT_CA_CERTS | Path to gRPC client CA certificate                     | ""      |

## Deployment

To start the service outside of the container, execute the following shell script:

```bash
# download the latest version of the service
go get github.com/ultravioletrs/cocos

cd $GOPATH/src/github.com/ultravioletrs/cocos

# compile the agent
make agent

# set the environment variables and run the service
./build/cocos-agent
```

## Usage

For more information about service capabilities and its usage, please check out the [README documentation](../README.md).
