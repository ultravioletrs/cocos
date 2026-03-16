# CVMS Test Server

The Agent has a CVMS gRPC client that connects to a CVMS (CVM Management Service) server. The server sends computation run requests to the agent via gRPC. Once the agent receives the computation request, it launches an agent gRPC server and initializes with the computation manifest. The agent then passes logs and events back to the CVMS server.

`main.go` is a sample implementation of a CVMS server for testing purposes. It demonstrates both **direct upload mode** (legacy) and **remote resource mode** (with KBS attestation).

## Configuration

The service is configured using environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable         | Description                              | Default |
| ---------------- | ---------------------------------------- | ------- |
| HOST             | CVMS server gRPC host                    |         |
| PORT             | CVMS server gRPC port                    | 7001    |
| SERVER_CERT      | Path to server certificate in pem format |         |
| SERVER_KEY       | Path to server key in pem format         |         |

## Command-Line Flags

### Required Flags

| Flag | Description |
| ---- | ----------- |
| `-public-key-path` | Path to the public key file (PEM format) |
| `-attested-tls-bool` | Whether to use attested TLS ('true' or 'false') |

### Direct Upload Mode Flags

| Flag | Description |
| ---- | ----------- |
| `-algo-path` | Path to the algorithm file (required if not using remote algorithm) |
| `-data-paths` | Comma-separated paths to dataset files (optional) |

### Remote Resource Mode Flags

| Flag | Description |
| ---- | ----------- |
| `-kbs-url` | KBS endpoint URL (e.g., 'http://localhost:8080') |
| `-algo-source-url` | Algorithm source URL (s3://bucket/key or https://...) |
| `-algo-kbs-path` | Algorithm KBS resource path (e.g., 'default/key/algo-key') |
| `-dataset-source-urls` | Comma-separated dataset source URLs |
| `-dataset-kbs-paths` | Comma-separated dataset KBS resource paths |

### Optional Flags

| Flag | Description |
| ---- | ----------- |
| `-client-ca-file` | Client CA root certificate file path (for mTLS) |

## Running

### Direct Upload Mode (Legacy)

In this mode, the algorithm and datasets are uploaded directly via the CLI, and the CVMS server only sends their hashes in the manifest.

```bash
go run ./test/cvms/main.go \
  -algo-path /path/to/algorithm.wasm \
  -data-paths /path/to/data1.csv,/path/to/data2.csv \
  -public-key-path /path/to/public_key.pem \
  -attested-tls-bool false
```

### Remote Resource Mode (with KBS)

In this mode, the CVMS server specifies remote URLs for encrypted resources, and the agent downloads and decrypts them using KBS attestation.

**Remote Algorithm Only:**

```bash
go run ./test/cvms/main.go \
  -public-key-path /path/to/public_key.pem \
  -attested-tls-bool false \
  -kbs-url http://localhost:8080 \
  -algo-source-url s3://cocos-resources/algorithm.wasm.enc \
  -algo-kbs-path default/key/algorithm-key
```

**Remote Algorithm and Datasets:**

```bash
go run ./test/cvms/main.go \
  -public-key-path /path/to/public_key.pem \
  -attested-tls-bool false \
  -kbs-url http://localhost:8080 \
  -algo-source-url s3://cocos-resources/algorithm.wasm.enc \
  -algo-kbs-path default/key/algorithm-key \
  -dataset-source-urls https://example.com/data1.csv.enc,https://example.com/data2.csv.enc \
  -dataset-kbs-paths default/key/data1-key,default/key/data2-key
```

**Mixed Mode (Remote Algorithm + Direct Datasets):**

```bash
go run ./test/cvms/main.go \
  -algo-source-url s3://cocos-resources/algorithm.wasm.enc \
  -algo-kbs-path default/key/algorithm-key \
  -data-paths /path/to/data1.csv,/path/to/data2.csv \
  -public-key-path /path/to/public_key.pem \
  -attested-tls-bool false \
  -kbs-url http://localhost:8080
```

### With Attested TLS

```bash
go run ./test/cvms/main.go \
  -algo-path /path/to/algorithm.wasm \
  -data-paths /path/to/data1.csv \
  -public-key-path /path/to/public_key.pem \
  -attested-tls-bool true \
  -client-ca-file /path/to/ca.pem
```

## Notes

- **Either** `-algo-path` **OR** (`-algo-source-url` AND `-algo-kbs-path`) must be provided
- When using remote datasets, `-dataset-source-urls` and `-dataset-kbs-paths` must have the same number of comma-separated values
- The `-kbs-url` flag should be provided when using any remote resources
- For remote resources, the hash values in the manifest are currently placeholders (all zeros). In production, these should be the actual hashes of the **decrypted** data
- See [TESTING_REMOTE_RESOURCES.md](../TESTING_REMOTE_RESOURCES.md) for a complete guide on testing remote resource downloads with KBS attestation

## Architecture

```
┌─────────────┐                  ┌─────────────┐
│ CVMS Server │ ────manifest───▶ │    Agent    │
│ (this test) │ ◀───logs/events─ │             │
└─────────────┘                  └──────┬──────┘
                                        │
                                        │ (if remote resources)
                                        ▼
                          ┌─────────────────────────┐
                          │  Registry (S3/HTTP)     │
                          │  + KBS (Key Broker)     │
                          └─────────────────────────┘
```

The agent downloads encrypted resources from the registry and retrieves decryption keys from KBS using TEE attestation.
