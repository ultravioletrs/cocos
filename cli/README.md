# Agent CLI

This repository contains the command-line interface (CLI) tool for interacting with the Agent and manager service. The CLI allows you to perform various tasks such as running computations, uploading algorithm and datasets, and retrieving results.

## Build

From the project root:

```bash
make cli
```

## Usage

#### Run Computation

To run a computation, use the following command:

```bash
./build/cocos-cli manager run --computation '{"name": "my-computation"}'
```

#### Get attestation
Retrieves attestation information from the SEV guest and saves it to a file.
To retrieve attestation from agent, use the following command:
```bash
./build/cocos-cli agent attestation get '<report_data>'
```

#### Validate attestation
Validates the retrieved attestation information against a specified policy and checks its authenticity.
To validate and verify attestation from agent, use the following command:
```bash
./build/cocos-cli agent attestation validate '<attestation>' --report_data '<report_data>'
```
##### Flags
- --config: Path to a JSON file containing the validation configuration. This can be used to override individual flags.
- --report_data: Hex-encoded string representing the attestation report data. (Required for the validate command)
- --host_data: Hex-encoded string representing the expected HOST_DATA field.
- --family_id: Hex-encoded string representing the expected FAMILY_ID field.
- --image_id: Hex-encoded string representing the expected IMAGE_ID field.
- --report_id: Hex-encoded string representing the expected REPORT_ID field.
- --report_id_ma: Hex-encoded string representing the expected REPORT_ID_MA field.
- --measurement: Hex-encoded string representing the expected MEASUREMENT field.
- --chip_id: Hex-encoded string representing the expected CHIP_ID field.
- --minimum_tcb: Minimum acceptable value for CURRENT_TCB, COMMITTED_TCB, and REPORTED_TCB.
- --minimum_launch_tcb: Minimum acceptable value for LAUNCH_TCB.
- --minimum_guest_svn: Minimum acceptable SnpPolicy.
- --minimum_build: Minimum 8-bit build number for AMD-SP firmware.
- --check_crl: Download and check the CRL for revoked certificates (default: false).
- --disallow_network: If true, disallows network downloads for verification (default: false).
- --timeout: Duration to continue retrying failed HTTP requests (default: 2 minutes).
- --max_retry_delay: Maximum duration to wait between HTTP request retries (default: 30 seconds).
- --require_author_key: Require that AUTHOR_KEY_EN is set to 1 (default: false).
- --require_id_block: Require that the VM was launched with an ID_BLOCK signed by a trusted key (default: false).
- --permit_provisional_software: Allow provisional firmware (default: false).
- --platform_info: Maximum acceptable PLATFORM_INFO field bit-wise (optional).
- --minimum_version: Minimum AMD-SP firmware API version (major.minor) (optional).
- --trusted_author_keys: Paths to x.509 certificates of trusted author keys (optional).
- --trusted_author_key_hashes: Hex-encoded SHA-384 hashes of trusted author keys (optional).
- --trusted_id_keys: Paths to x.509 certificates of trusted identity keys (optional).
- --trusted_id_key_hashes: Hex-encoded SHA-384 hashes of trusted identity keys (optional).
- --product: AMD product name for the chip that generated the attestation report (optional).
- --stepping: Machine stepping for the chip that generated the attestation report (optional).
- --CA_bundles_paths: Paths to CA bundles for the AMD product (optional).
- --CA_bundles: PEM format CA bundles for the AMD product (optional).

#### Upload Algorithm

To upload an algorithm, use the following command:

```bash
./build/cocos-cli agent algo /path/to/algorithm
```

#### Upload Dataset

To upload a dataset, use the following command:

```bash
./build/cocos-cli agent data /path/to/dataset.csv
```

#### Retrieve result

To retrieve the computation result, use the following command:

```bash
./build/cocos-cli agent result
```