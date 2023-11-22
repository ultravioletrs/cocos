# Manager

Manager service provides a barebones HTTP and gRPC API and Service interface implementation for the development of the manager service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable                 | Description                                              | Default                           |
| ------------------------ | -------------------------------------------------------- | --------------------------------- |
| MANAGER_LOG_LEVEL        | Log level for manager service (debug, info, warn, error) | info                              |
| MANAGER_HTTP_HOST        | Manager service HTTP host                                |                                   |
| MANAGER_HTTP_PORT        | Manager service HTTP port                                | 9021                              |
| MANAGER_HTTP_SERVER_CERT | Path to server certificate in pem format                 |                                   |
| MANAGER_HTTP_SERVER_KEY  | Path to server key in pem format                         |                                   |
| MANAGER_GRPC_HOST        | Manager service gRPC host                                |                                   |
| MANAGER_GRPC_PORT        | Manager service gRPC port                                | 7001                              |
| MANAGER_GRPC_SERVER_CERT | Path to server certificate in pem format                 |                                   |
| MANAGER_GRPC_SERVER_KEY  | Path to server key in pem format                         |                                   |
| AGENT_GRPC_URL           | Agent service gRPC URL                                   | localhost:7002                    |
| AGENT_GRPC_TIMEOUT       | Agent service gRPC timeout                               | 1s                                |
| AGENT_GRPC_CA_CERTS      | Agent service gRPC CA certificates                       |                                   |
| AGENT_GRPC_CLIENT_TLS    | Agent service gRPC client TLS                            | false                             |
| MANAGER_JAEGER_URL       | Jaeger server URL                                        | http://localhost:14268/api/traces |
| MANAGER_INSTANCE_ID      | Manager service instance ID                              |                                   |

## Deployment

To start the service outside of the container, execute the following shell script:

```bash
# download the latest version of the service
go get github.com/ultravioletrs/cocos

cd $GOPATH/src/github.com/ultravioletrs/cocos

# compile the manager
make manager

# copy binary to bin
make install

# set the environment variables and run the service
./build/cocos-manager
```

## Usage

For more information about service capabilities and its usage, please check out the [README documentation](../README.md).
