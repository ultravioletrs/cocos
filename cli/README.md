# CoCoS CLI

The CoCoS CLI (`cocos-cli`) is the command-line interface for interacting with the Agent and Manager services. It lets operators and data owners upload algorithms and datasets, retrieve results, perform attestation, compute checksums, and measure IGVM files.

## Build

From the repository root:

```bash
make cli
# Output: build/cocos-cli
```

## Commands

| Command | Description |
| --- | --- |
| `algo` | Upload an encrypted algorithm to the Agent |
| `data` | Upload an encrypted dataset to the Agent |
| `result` | Download the encrypted computation result from the Agent |
| `attestation get` | Retrieve a hardware attestation report from the Agent |
| `attestation validate` | Validate an attestation report against a policy |
| `checksum` | Compute the SHA-256 checksum of a file (required for manifests) |
| `igvmmeasure` | Calculate the launch measurement of an IGVM file |

---

### `algo` — Upload Algorithm

```bash
./build/cocos-cli algo <path/to/algorithm> <private_key.pem> [flags]
```

| Flag | Description | Default |
| --- | --- | --- |
| `-a`, `--algorithm` | Algorithm type (`bin`, `python`, `wasm`, `docker`) | `bin` |
| `--args` | Arguments to pass to the algorithm | — |
| `--python-runtime` | Python runtime binary name | `python3` |
| `-r`, `--requirements` | Path to Python requirements file | — |

---

### `data` — Upload Dataset

```bash
./build/cocos-cli data <path/to/dataset> <private_key.pem> [flags]
```

Directories are compressed in transit. The Agent stores them compressed unless `--decompress` is set.

| Flag | Description |
| --- | --- |
| `-d`, `--decompress` | Decompress the dataset inside the Agent after upload |

---

### `result` — Retrieve Result

```bash
./build/cocos-cli result <private_key.pem>
```

Downloads and decrypts the computation result from the Agent.

---

### `attestation get` — Retrieve Attestation

Fetches the hardware attestation report from the SEV guest and saves it to a file.

```bash
./build/cocos-cli attestation get '<report_data>'
```

---

### `attestation validate` — Validate Attestation

Validates a retrieved attestation report against a policy and checks its authenticity.

```bash
./build/cocos-cli attestation validate '<attestation>' --report_data '<report_data>'
```

| Flag | Description | Default |
| --- | --- | --- |
| `--config` | Path to a JSON file containing validation configuration | — |
| `--report_data` | Hex-encoded attestation report data **(required)** | — |
| `--host_data` | Expected `HOST_DATA` field (hex) | — |
| `--family_id` | Expected `FAMILY_ID` field (hex) | — |
| `--image_id` | Expected `IMAGE_ID` field (hex) | — |
| `--report_id` | Expected `REPORT_ID` field (hex) | — |
| `--report_id_ma` | Expected `REPORT_ID_MA` field (hex) | — |
| `--measurement` | Expected `MEASUREMENT` field (hex) | — |
| `--chip_id` | Expected `CHIP_ID` field (hex) | — |
| `--minimum_tcb` | Minimum acceptable TCB value | — |
| `--minimum_launch_tcb` | Minimum acceptable launch TCB value | — |
| `--minimum_guest_svn` | Minimum acceptable SnpPolicy guest SVN | — |
| `--minimum_build` | Minimum AMD-SP firmware build number | — |
| `--minimum_version` | Minimum AMD-SP firmware API version (`major.minor`) | — |
| `--check_crl` | Download and check the CRL for revoked certificates | `false` |
| `--disallow_network` | Disallow network downloads during verification | `false` |
| `--timeout` | Duration to retry failed HTTP requests | `2m` |
| `--max_retry_delay` | Maximum wait between HTTP retries | `30s` |
| `--require_author_key` | Require `AUTHOR_KEY_EN` to be set to 1 | `false` |
| `--require_id_block` | Require the VM was launched with a trusted ID block | `false` |
| `--permit_provisional_software` | Allow provisional firmware | `false` |
| `--platform_info` | Maximum acceptable `PLATFORM_INFO` field (bit-wise) | — |
| `--trusted_author_keys` | Paths to x.509 certificates of trusted author keys | — |
| `--trusted_author_key_hashes` | SHA-384 hashes of trusted author keys (hex) | — |
| `--trusted_id_keys` | Paths to x.509 certificates of trusted identity keys | — |
| `--trusted_id_key_hashes` | SHA-384 hashes of trusted identity keys (hex) | — |
| `--product` | AMD product name for the attestation chip | — |
| `--stepping` | Machine stepping for the attestation chip | — |
| `--CA_bundles_paths` | Paths to CA bundles for the AMD product | — |
| `--CA_bundles` | PEM-format CA bundles for the AMD product | — |

---

### `checksum` — Compute File Checksum

Computation manifests require SHA-256 checksums for the algorithm and each dataset.

```bash
./build/cocos-cli checksum <path/to/file>
```

---

### `igvmmeasure` — Measure IGVM File

Calculates the launch measurement for an IGVM file. The output can be used to pre-compute the expected measurement in an attestation policy.

```bash
./build/cocos-cli igvmmeasure <path/to/igvm/file>
```

Example output:

```text
91c4929bec2d0ecf11a708e09f0a57d7d82208bcba2451564444a4b01c22d047995ca27f9053f86de4e8063e9f810548
```

---

## Example — End-to-End Workflow

The following shows a complete flow: generate keys, compute checksums, upload the algorithm and dataset, and retrieve the result.

```bash
# 1. Generate an Ed25519 key pair
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# 2. Compute checksums (needed when defining the computation manifest)
./build/cocos-cli checksum ./my_algorithm.py
./build/cocos-cli checksum ./dataset.csv

# 3. Upload the algorithm (Python example)
./build/cocos-cli algo ./my_algorithm.py private.pem \
  --algorithm python \
  --requirements ./requirements.txt

# 4. Upload the dataset
./build/cocos-cli data ./dataset.csv private.pem

# 5. Retrieve the encrypted result
./build/cocos-cli result private.pem
```
