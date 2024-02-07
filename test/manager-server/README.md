# Manager test server
Manager service is a grpc client. It connects to a server and sends a whoAmIRequest.
The server then responds with a run computation request. Once manager service receives the computation request it will launch an agent service in a virtual machine and pass the computation manifest. Agent will then pass logs and events to manager which are forwarded to the server. `main.go` is a sample of how such a server would be implemented. This is a very simple example for testing purposes.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable         | Description                              | Default |
| ---------------- | ---------------------------------------- | ------- |
| HOST             | Manager service gRPC host                |         |
| PORT             | Manager service gRPC port                | 7001    |
| SERVER_CERT      | Path to server certificate in pem format |         |
| SERVER_KEY       | Path to server key in pem format         |         |

## Running
```shell
go run main.go
```
