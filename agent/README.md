# Agent

Agent service provides a barebones HTTP and gRPC API and Service interface implementation for the development of the agent service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable                 | Description                                            | Default                        |
| ------------------------ | ------------------------------------------------------ | ------------------------------ |
| AGENT_LOG_LEVEL          | Log level for agent service (debug, info, warn, error) | info                           |
| AGENT_HTTP_HOST          | Agent service HTTP host                                | ""                             |
| AGENT_HTTP_PORT          | Agent service HTTP port                                | 9031                           |
| AGENT_HTTP_SERVER_CERT   | Path to HTTP server certificate in pem format          | ""                             |
| AGENT_HTTP_SERVER_KEY    | Path to HTTP server key in pem format                  | ""                             |
| AGENT_GRPC_HOST          | Agent service gRPC host                                | ""                             |
| AGENT_GRPC_PORT          | Agent service gRPC port                                | 7002                           |
| AGENT_GRPC_SERVER_CERT   | Path to gRPC server certificate in pem format          | ""                             |
| AGENT_GRPC_SERVER_KEY    | Path to gRPC server key in pem format                  | ""                             |
| AGENT_JAEGER_URL         | Jaeger server URL                                      | http://jaeger:14268/api/traces |
| COCOS_MESSAGE_BROKER_URL | Message broker URL                                     | nats://localhost:4222          |

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
