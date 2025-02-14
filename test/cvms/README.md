# Cvms Server
Agent has a cvms grpc client. It connects to cvms server.
The server then responds with a run computation request. Once agent receives the computation request it will launch an agent gRPC server and initliaze agent with a new computation manifest. Agent will then pass logs and events to cvms server. `main.go` is a sample of how such a server would be implemented. This is a very simple example for testing purposes.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable         | Description                              | Default |
| ---------------- | ---------------------------------------- | ------- |
| HOST             | Computations service gRPC host           |         |
| PORT             | Computations service gRPC port           | 7001    |
| SERVER_CERT      | Path to server certificate in pem format |         |
| SERVER_KEY       | Path to server key in pem format         |         |

## Running
```shell
go run main.go <algo_path> <public_key_path> <attested_tls_bool> <dataset(s)_path> 
```
