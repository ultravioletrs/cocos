# Testing Remote Resource Download with KBS Attestation

This guide provides step-by-step instructions for testing the encrypted resource download flow in the cocos-ai agent using the CVMS (CVM Management Service) test server.

## Architecture Overview

The cocos-ai system uses a **CVMS → Agent** architecture for computation management:

1. **CVMS Server** sends computation manifests to the Agent via gRPC
2. **Agent** receives the manifest and downloads remote resources (if configured)
3. **Agent** performs KBS attestation to retrieve decryption keys
4. **Agent** decrypts and executes the computation
5. **CLI** is used only for direct algorithm/dataset uploads (legacy mode) or retrieving results

> [!IMPORTANT]
> The CLI does **not** have a `computation create` command. Computation manifests are sent by CVMS servers, not the CLI.

## Prerequisites

### 1. KBS Setup

The Key Broker Service (KBS) from the Confidential Containers trustee project is required for key management.

**Deploy KBS using Docker Compose:**

```bash
# Clone the trustee repository
git clone https://github.com/confidential-containers/trustee.git
cd trustee

# Start KBS using docker compose
docker compose up -d kbs

# Verify KBS is running
curl http://localhost:8080/kbs/v0/auth
```

**Configure KBS policies:**

The KBS needs to be configured to release keys only to attested workloads. See the [trustee documentation](https://github.com/confidential-containers/trustee) for policy configuration details.

### 2. Registry Setup

You need a registry to host encrypted resources. Options include:

**Option A: MinIO (S3-compatible, local testing)**

```bash
# Run MinIO locally
docker run -d \
  -p 9000:9000 \
  -p 9001:9001 \
  --name minio \
  -e "MINIO_ROOT_USER=minioadmin" \
  -e "MINIO_ROOT_PASSWORD=minioadmin" \
  quay.io/minio/minio server /data --console-address ":9001"

# Access MinIO console at http://localhost:9001
# Create a bucket named "cocos-resources"
```

**Option B: AWS S3**

Use an existing S3 bucket or create a new one:

```bash
aws s3 mb s3://my-cocos-resources
```

**Option C: HTTP/HTTPS Server**

Any web server can host encrypted resources:

```bash
# Simple Python HTTP server
python3 -m http.server 8000
```

### 3. Agent Setup

> [!NOTE]
> The agent is typically deployed in a VM environment using the manager and the `create-vm` CLI command. The manager uses the buildroot image/HAL to provision VMs and automatically configures environment variables inside the VM.

**Option A: Deploy Agent in VM (Recommended)**

The `create-vm` command requires the manager to be running. Follow these steps:

**Step 1: Start the Manager**

The manager must be running before you can create VMs. See the [Manager README](file:///home/sammyk/Documents/cocos-ai/manager/README.md) for detailed setup instructions.

Basic example:

```bash
# Build the manager
cd /path/to/cocos-ai
make manager

# Start the manager with basic configuration
MANAGER_GRPC_URL=localhost:7001 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_USE_SUDO=false \
MANAGER_QEMU_DISK_IMG_KERNEL_FILE=img/bzImage \
MANAGER_QEMU_DISK_IMG_ROOTFS_FILE=img/rootfs.cpio.gz \
./build/cocos-manager
```

> [!IMPORTANT]
> Before starting the manager, ensure you have:
> - Built the buildroot image (see [HAL Linux README](file:///home/sammyk/Documents/cocos-ai/hal/linux/README.md))
> - Copied `bzImage` and `rootfs.cpio.gz` to the `img/` directory

**Step 2: Create the VM with AWS Credentials**

Pass AWS credentials directly via CLI flags. The manager will automatically configure these as environment variables inside the VM:

```bash
# Get your host IP address (not localhost, as VM needs to access from within)
HOST_IP=$(ip route get 1 | awk '{print $7; exit}')

# Create VM with AWS credentials for S3/MinIO access
./build/cocos-cli create-vm \
  --server-url localhost:7001 \
  --log-level debug \
  --aws-access-key-id minioadmin \
  --aws-secret-access-key minioadmin \
  --aws-endpoint-url http://$HOST_IP:9000 \
  --aws-region us-east-1
```

> [!NOTE]
> The AWS credentials are passed via the manager's CreateVM API and automatically written to the VM's environment file. The agent inside the VM will have access to these environment variables for S3/MinIO operations.

**Available AWS Flags:**
- `--aws-access-key-id`: AWS Access Key ID for S3/MinIO
- `--aws-secret-access-key`: AWS Secret Access Key for S3/MinIO  
- `--aws-endpoint-url`: AWS Endpoint URL (for MinIO or custom S3 endpoints)
- `--aws-region`: AWS Region (e.g., us-east-1)

The manager will automatically:
- Provision a new VM using the buildroot image
- Create an environment file with the provided AWS credentials
- Start the agent inside the VM with the configured environment
- Forward the agent port to the host

**Option B: Build Agent Directly (Development/Testing)**

For development and testing without the manager:

```bash
cd /path/to/cocos-ai
export PATH=$PATH:/home/sammyk/go/bin
make agent
```

## Encrypting Resources for Testing

### 1. Generate Encryption Key

```bash
# Generate a 256-bit AES key
openssl rand -hex 32 > encryption.key
```

### 2. Encrypt Algorithm or Dataset

```bash
# Encrypt a file using AES-256-GCM
openssl enc -aes-256-cbc \
  -in ./test/manual/algo/lin_reg.py \
  -out algorithm.lin-reg-py.enc \
  -K $(cat encryption.key) \
  -iv $(openssl rand -hex 16)
```

### 3. Store Key in KBS

Upload the encryption key to KBS using the KBS client tool:

**Install KBS Client Tool:**

```bash
# Install the KBS client tool
cargo install --git https://github.com/confidential-containers/trustee kbs-client
```

**Locate Default Admin Keys:**

When KBS starts via docker compose, it automatically generates admin keys in the `kbs/config` directory:

```bash
cd trustee
ls kbs/config/
# You should see: private.key (ED25519), public.pub, token.key (EC), ca.key, etc.
```

> [!IMPORTANT]
> The `kbs-client` tool requires an **ED25519** private key. Use `private.key`, not `token.key` (which is an EC key and will cause parse errors).

**Upload the Encryption Key:**

Use the default `private.key` (ED25519 format) generated by KBS for authentication:

```bash
# Navigate to the trustee directory
cd trustee

# Use the KBS client tool to upload the resource
kbs-client --url http://localhost:8080 config \
  --auth-private-key kbs/config/private.key set-resource \
  --path default/key/algorithm-key --resource-file ../cocos-ai/encryption.key

# Output should look like:
# Set resource success 
# resource: YmJmM2ExMTk4ZWU4ODlmNzdhMjI3ZmUwMWUzMjk4NjRmZDZhMzdhMmQyMzEzNWVhOGUyYzVhMmViYzA3ZjBkMwo=
```

> [!NOTE]
> The KBS docker compose setup automatically generates and configures admin keys on first startup. You can use the default `kbs/config/private.key` for admin operations without additional configuration.

### 4. Upload Encrypted Resource to Registry

**For MinIO:**

```bash
# Install MinIO client (mc)
# For Linux/macOS:
curl https://dl.min.io/client/mc/release/linux-amd64/mc \
  --create-dirs \
  -o $HOME/minio-binaries/mc
chmod +x $HOME/minio-binaries/mc
export PATH=$PATH:$HOME/minio-binaries/

# For Windows (PowerShell):
# Invoke-WebRequest -Uri "https://dl.min.io/client/mc/release/windows-amd64/mc.exe" -OutFile "C:\minio-binaries\mc.exe"

# Using MinIO client (mc)
mc alias set local http://localhost:9000 minioadmin minioadmin
mc cp algorithm.lin-reg-py.enc local/cocos-resources/algorithm.lin-reg-py.enc
```

**For S3:**

```bash
aws s3 cp algorithm.lin-reg-py.enc s3://my-cocos-resources/algorithm.lin-reg-py.enc
```

**For HTTP server:**

```bash
# Copy to server directory
cp algorithm.lin-reg-py.enc /path/to/http/server/root/
```

## Testing Procedure

> [!NOTE]
> The correct startup order is: **Manager → CVMS → Agent (via create-vm CLI)**. The agent connects to CVMS on startup, and CVMS must be accessible from within the VM.

### 1. Find Your Host IP Address

When running the CVMS server, use an IP address that is reachable from the virtual machine — not `localhost`.

```bash
# Method 1: Using ip command
ip a

# Method 2: Using ip route (more reliable for getting primary IP)
ip route get 1 | awk '{print $7; exit}'
```

Look for your network interface (such as `wlan0` for WiFi or `eth0` for Ethernet) and note the IP address. For example:

```
2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 12:34:56:78:9a:bc brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0
```

In this example, the IP address is `192.168.1.100`. This address will be used for both the CVMS server and in the `create-vm` command.

### 2. Start the Manager

The manager must be running to create VMs. See the [Manager README](file:///home/sammyk/Documents/cocos-ai/manager/README.md) for detailed setup.

```bash
# Build the manager
cd /path/to/cocos-ai
make manager

# Locate OVMF files (if not already known)
sudo find / -name OVMF_CODE.fd
sudo find / -name OVMF_VARS.fd

# Start the manager
MANAGER_GRPC_HOST=localhost \
MANAGER_GRPC_PORT=7002 \
MANAGER_LOG_LEVEL=debug \
MANAGER_QEMU_ENABLE_SEV_SNP=false \
MANAGER_QEMU_OVMF_CODE_FILE=/usr/share/OVMF/OVMF_CODE.fd \
MANAGER_QEMU_OVMF_VARS_FILE=/usr/share/OVMF/OVMF_VARS.fd \
MANAGER_QEMU_DISK_IMG_KERNEL_FILE=img/bzImage \
MANAGER_QEMU_DISK_IMG_ROOTFS_FILE=img/rootfs.cpio.gz \
./build/cocos-manager
```

Expected output:
```
{"time":"2025-06-25T17:21:44.3400595+02:00","level":"INFO","msg":"manager service gRPC server listening at localhost:7002 without TLS"}
```

> [!IMPORTANT]
> Before starting the manager, ensure you have:
> - Built the buildroot image (see [HAL Linux README](file:///home/sammyk/Documents/cocos-ai/hal/linux/README.md))
> - Copied `bzImage` and `rootfs.cpio.gz` to the `img/` directory

### 3. Start the CVMS Test Server

> [!IMPORTANT]
> The CVMS server must be started **before** the agent and must use a host IP address that is reachable from within the VM (not `localhost`). See the [CVMS README](file:///home/sammyk/Documents/cocos-ai/test/cvms/README.md) for more details.

```bash
# Get your host IP address (reachable from VM)
HOST_IP=$(ip route get 1 | awk '{print $7; exit}')

# Build the test CVMS server
go build -o build/cvms-test ./test/cvms/main.go

# Start CVMS with host-reachable address
HOST=$HOST_IP PORT=7001 ./build/cvms-test \
  -public-key-path ./public.pem \
  -attested-tls-bool false \
  -kbs-url http://$HOST_IP:8080 \
  -algo-source-url s3://cocos-resources/algorithm.lin-reg-py.enc \
  -algo-kbs-path default/key/algorithm-key \
  -data-paths ./test/manual/data/iris.csv
```

Expected output:
```
{"time":"2025-06-25T14:52:58.693344502+02:00","level":"INFO","msg":"cvms_test_server service gRPC server listening at 192.168.1.100:7001 without TLS"}
```

**Alternative modes:**

**Direct Upload Mode (legacy):**
```bash
HOST=$HOST_IP PORT=7001 ./build/cvms-test \
  -algo-path ./test/manual/algo/addition.py \
  -data-paths ./path/to/data1.csv,./path/to/data2.csv \
  -public-key-path ./public.pem \
  -attested-tls-bool false
```

**Mixed Mode (remote algorithm + direct datasets):**
```bash
HOST=$HOST_IP PORT=7001 ./build/cvms-test \
  -public-key-path ./public.pem \
  -attested-tls-bool false \
  -kbs-url http://$HOST_IP:8080 \
  -algo-source-url s3://cocos-resources/algorithm.lin-reg-py.enc \
  -algo-kbs-path default/key/algorithm-key \
  -data-paths ./test/manual/data/iris.csv
```

### 4. Create VM and Start Agent via CLI

Use the CLI to create a VM with the agent configuration. The agent will automatically connect to the CVMS server.

```bash
# Get your host IP address
HOST_IP=$(ip route get 1 | awk '{print $7; exit}')

# Set manager URL
export MANAGER_GRPC_URL=localhost:7002

# Create VM with full configuration
./build/cocos-cli create-vm \
  --server-url $HOST_IP:7001 \
  --log-level debug \
  --aws-access-key-id minioadmin \
  --aws-secret-access-key minioadmin \
  --aws-endpoint-url http://$HOST_IP:9000 \
  --aws-region us-east-1
```

Expected output:
```
🔗 Connected to manager using without TLS
🔗 Creating a new virtual machine
✅ Virtual machine created successfully with id e71cdcf5-21c0-4e1d-9471-ac6b4389d5f3 and port 6100
```

> [!NOTE]
> - `--server-url`: CVMS server address (must be reachable from VM, use host IP not localhost)
> - AWS flags: Credentials for S3/MinIO access from within the VM
> - The manager will create the VM and configure the agent with these settings
> - The agent will automatically connect to CVMS at the specified `--server-url`
> - The forwarded port (e.g., 6100) is used for CLI operations like uploading assets and retrieving results

**Verify VM is running:**

```bash
# Check for running QEMU processes
ps aux | grep qemu
```

**Verify agent is running in the VM:**

```bash
# SSH into the VM or use the VM console
systemctl status cocos-agent
# Or check logs
journalctl -u cocos-agent -f
```

### 4. Monitor Agent Logs

Watch the agent logs for download and decryption progress:

```bash
# Agent should log:
# - "downloading encrypted resource"
# - "getting TEE evidence for attestation"
# - "attesting with KBS"
# - "attestation successful, token received"
# - "retrieving decryption key"
# - "decrypting resource"
# - "resource decrypted successfully"
```

### 5. Verify Computation Execution

The agent will automatically execute the computation after downloading and decrypting all resources. Monitor the agent logs for computation status.

### 6. Retrieve Results (Optional)

If you need to retrieve results via CLI:

```bash
./build/cocos-cli result ./path/to/private_key.pem
```

## Testing Scenarios

### Test 1: S3 Download with KBS Attestation

- Upload encrypted algorithm to MinIO/S3
- Store decryption key in KBS
- Run CVMS test server with S3 URL and KBS configuration
- Verify agent downloads, attests, retrieves key, and decrypts

### Test 2: HTTP Download with KBS Attestation

- Host encrypted dataset on HTTP server
- Store decryption key in KBS
- Run CVMS test server with HTTP URL and KBS configuration
- Verify download and decryption flow

### Test 3: Mixed Mode (Remote + Direct)

- Specify remote source for algorithm via CVMS flags
- Specify local dataset paths via CVMS flags
- Verify agent handles both flows correctly

### Test 4: Error Scenarios

**Network Failure:**
```bash
# Stop MinIO/registry
docker stop minio
# Run CVMS test server - should see retry attempts and eventual failure
```

**Invalid Decryption Key:**
```bash
# Store wrong key in KBS
# Run CVMS test server - should fail with decryption error
```

**Attestation Failure:**
```bash
# Misconfigure KBS policies to reject attestation
# Run CVMS test server - should fail during key retrieval
```

**Missing KBS Configuration:**
```bash
# Run CVMS with remote sources but no --kbs-url
# Should fail validation or during resource download
```

### Test 5: Backward Compatibility

- Run CVMS test server in direct upload mode (no remote resource flags)
- Verify no regression in existing functionality

## Troubleshooting

### Agent fails to download from S3

**Check:**
- AWS credentials are set correctly in agent environment
- S3 bucket and object exist
- Network connectivity to S3/MinIO

**Debug:**
```bash
# Test S3 access manually
aws s3 ls s3://cocos-resources/
```

### Agent fails to retrieve key from KBS

**Check:**
- KBS is running and accessible
- Attestation-agent is properly configured
- KBS policies allow key release to this workload

**Debug:**
```bash
# Test KBS connectivity
curl http://localhost:8080/kbs/v0/auth

# Check attestation-agent logs
journalctl -u attestation-agent -f
```

### Decryption fails

**Check:**
- Encryption key in KBS matches the key used to encrypt the resource
- Resource was encrypted using AES-GCM format
- KBS resource path in CVMS flags is correct

**Debug:**
```bash
# Manually decrypt to verify key
openssl enc -d -aes-256-cbc \
  -in algorithm.lin-reg-py.enc \
  -out lin_reg.py \
  -K $(cat encryption.key) \
  -iv <iv_used_during_encryption>
```

### Agent logs show "resource not found"

**Check:**
- URL in CVMS flags is correct and accessible
- For S3: bucket and object names are correct
- For HTTP: server is running and file exists

**Debug:**
```bash
# Test URL accessibility
curl -I <resource_url>
```

### CVMS test server validation errors

**Check:**
- Either `--algo-path` OR (`--algo-source-url` AND `--algo-kbs-path`) must be provided
- If using remote datasets, `--dataset-source-urls` and `--dataset-kbs-paths` must have the same count
- `--public-key-path` is always required
- `--attested-tls-bool` must be 'true' or 'false'

## Expected Behavior

1. **CVMS server starts** and waits for agent connection
2. **Agent connects** to CVMS server
3. **CVMS sends computation manifest** with remote resource sources (if configured)
4. **Agent validates manifest** including KBS configuration
5. **For each remote resource:**
   - Download encrypted resource from registry
   - Perform attestation with KBS
   - Retrieve decryption key from KBS
   - Decrypt resource using retrieved key
   - Verify hash matches manifest (if provided)
6. **Agent executes computation** with downloaded/decrypted resources
7. **Results are available** for download via CLI (optional)

## Performance Considerations

- **Download time** depends on resource size and network speed
- **Attestation overhead** adds ~1-2 seconds per resource
- **Decryption** is fast (< 1 second for typical resources)
- **Retry logic** may add delays on network failures

## Security Notes

- Decryption keys are **never persisted to disk**
- Keys are **zeroed in memory** after use
- **Attestation ensures** only trusted workloads receive keys
- **TLS should be used** for KBS communication in production
- **S3 buckets should be private** with appropriate access controls

## Next Steps

After successful testing:

1. Configure production KBS with proper policies
2. Set up production S3 buckets with encryption
3. Integrate with CI/CD for automated resource uploads
4. Monitor agent metrics for download performance
5. Set up alerts for attestation failures

## Additional Resources

- [Confidential Containers Trustee Documentation](https://github.com/confidential-containers/trustee)
- [KBS API Reference](https://github.com/confidential-containers/trustee/tree/main/kbs)
- [Attestation Agent Documentation](https://github.com/confidential-containers/guest-components/tree/main/attestation-agent)
- [Cocos AI Documentation](https://docs.cocos.ultraviolet.rs)
- [CVMS Test Server README](file:///home/sammyk/Documents/cocos-ai/test/cvms/README.md)
