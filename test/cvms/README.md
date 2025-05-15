# Cvms Server
Agent has a cvms grpc client. It connects to cvms server.
The server then responds with a run computation request. Once agent receives the computation request it will launch an agent gRPC server and initliaze agent with a new computation manifest. Agent will then pass logs and events to cvms server. `main.go` is a sample of how such a server would be implemented. This is a very simple example for testing purposes.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable         | Description                              | Default |
| ---------------- | ---------------------------------------- | ------- |
| HOST             | CVMS server gRPC host                    |         |
| PORT             | CVMS server gRPC port                    | 7001    |
| SERVER_CERT      | Path to server certificate in pem format |         |
| SERVER_KEY       | Path to server key in pem format         |         |

## Running
```shell
Usage of tests/cvms/main.go:
  -algo-path string
        Path to the algorithm
  -attested-tls-bool string
        Should aTLS be used, must be 'true' or 'false'
  -ca-url string
        URL for certificate authority, optional flag that can only be used if aTLS is enabled
  -cvm-id string
        UUID for a CVM, optional flag that can only be used if aTLS is enabled
  -data-paths string
        Paths to data sources, list of string separated with commas
  -public-key-path string
        Path to the public key file

# Example
go run ./tests/cvms/main.go -algo-path <alog_path> -attested-tls-bool false -data-paths <data_paths> -public-key-path <public_key_path>
```
