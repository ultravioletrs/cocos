# Attestation Service

The Attestation Service retrieves and packages hardware attestation evidence from the underlying TEE platform (AMD SEV-SNP, Intel TDX, vTPM, or Azure MAA). It runs inside the CVM alongside the Agent and exposes a Unix domain socket that other in-CVM services use to request attestation tokens.

## Overview

When a caller requests attestation, the service:

1. Determines the active TEE platform automatically
2. Fetches the raw hardware attestation report (SEV-SNP report, TDX quote, or vTPM PCR measurements)
3. Wraps the report in an Entity Attestation Token (EAT) encoded as CBOR or JWT
4. Returns the signed token over the Unix socket

The socket path is `/run/cocos/attestation.sock` (fixed at compile time).

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `ATTESTATION_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `debug` |
| `ATTESTATION_VMPL` | Virtual Machine Privilege Level for SEV-SNP (0–3) | `2` |
| `ATTESTATION_EAT_FORMAT` | EAT token encoding format (`CBOR` or `JWT`) | `CBOR` |
| `ATTESTATION_EAT_ISSUER` | Issuer claim in the EAT token | `cocos-attestation-service` |
| `AGENT_MAA_URL` | Microsoft Azure Attestation service URL | `https://sharedeus2.eus2.attest.azure.net` |
| `AGENT_OS_BUILD` | OS build info for Azure attestation | `UVC` |
| `AGENT_OS_DISTRO` | OS distro info for Azure attestation | `UVC` |
| `AGENT_OS_TYPE` | OS type info for Azure attestation | `UVC` |
| `USE_CC_ATTESTATION_AGENT` | Use an external CC attestation-agent process | `false` |
| `CC_AGENT_ADDRESS` | Address of the external CC attestation-agent | `127.0.0.1:50002` |

## Deployment

```bash
# Build
make attestation-service

# Run (inside a CVM)
./build/cocos-attestation-service
```

The service listens on the Unix socket `/run/cocos/attestation.sock` immediately after start. It creates the socket directory `/run/cocos/` if it does not exist.

## Example

Other in-CVM services connect to the socket via gRPC. The `attestation-service` proto exposes two RPC methods:

| Method | Description |
| --- | --- |
| `FetchAttestation` | Request a hardware attestation report wrapped in an EAT token |
| `GetAzureToken` | Request an Azure MAA attestation token |

From the CLI on the host side, attestation can be retrieved through the Agent:

```bash
./build/cocos-cli attestation get '<hex_report_data>'
```
