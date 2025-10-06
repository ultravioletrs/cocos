# Agent

Agent service provides a barebones HTTP and gRPC API and Service interface implementation for the development of the agent service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable                       | Description                                                                                                   | Default                                         |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| AGENT_LOG_LEVEL                | Log level for agent service (debug, info, warn, error)                                                        | debug                                           |
| AGENT_VMPL                     | VMPL (Virtual Machine Privilege Level) for AMD SEV-SNP attestation (0-3)                                      | 2                                               |
| AGENT_GRPC_HOST                | Agent service gRPC host address                                                                               | 0.0.0.0                                         |
| AGENT_CVM_GRPC_HOST            | Agent service gRPC host                                                                                       | ""                                              |
| AGENT_CVM_GRPC_PORT            | Agent service gRPC port                                                                                       | 7001                                            |
| AGENT_CVM_GRPC_SERVER_CERT     | Path to gRPC server certificate in pem format                                                                 | ""                                              |
| AGENT_CVM_GRPC_SERVER_KEY      | Path to gRPC server key in pem format                                                                         | ""                                              |
| AGENT_CVM_GRPC_SERVER_CA_CERTS | Path to gRPC server CA certificate                                                                            | ""                                              |
| AGENT_CVM_GRPC_CLIENT_CA_CERTS | Path to gRPC client CA certificate                                                                            | ""                                              |
| AGENT_CVM_CA_URL               | URL for CA service, if provided it will be used for certificate generation, used only with aTLS at the moment | ""                                              |
| AGENT_CVM_ID                   | Unique identifier for the CVM (Confidential Virtual Machine)                                                  | ""                                              |
| AGENT_CERTS_TOKEN              | Authentication token for certificate service access                                                           | ""                                              |
| AGENT_MAA_URL                  | Microsoft Azure Attestation service URL for Azure attestation                                                 | https://sharedeus2.eus2.attest.azure.net        |
| AGENT_OS_BUILD                 | Operating system build information for attestation                                                            | UVC                                             |
| AGENT_OS_DISTRO                | Operating system distribution information for attestation                                                     | UVC                                             |
| AGENT_OS_TYPE                  | Operating system type information for attestation                                                             | UVC                                             |

## Deployment

To start the service outside of the container, execute the following shell script:

```bash
# Download the latest version of the service
git clone git@github.com:ultravioletrs/cocos.git

cd cocos

# Compile the service
make agent

# Run the service
./build/cocos-agent
```

## Usage

For more information about service capabilities and its usage, please check out the [README documentation](../README.md).
