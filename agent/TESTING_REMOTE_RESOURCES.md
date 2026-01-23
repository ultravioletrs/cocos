# Testing Remote Resources with CoCo Key Provider

This guide explains how to test Cocos with encrypted remote resources using the Confidential Containers Key Provider ecosystem.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         CVM (Agent)                          │
│                                                              │
│  ┌──────────┐    ┌────────────────┐    ┌─────────────────┐ │
│  │  Agent   │───▶│    Skopeo      │───▶│ CoCo Keyprovider│ │
│  └──────────┘    │  (ocicrypt)    │    │   (gRPC:50011)  │ │
│                  └────────────────┘    └────────┬────────┘ │
│                                                  │          │
│                                         ┌────────▼────────┐ │
│                                         │ Attestation     │ │
│                                         │ Agent (50002)   │ │
│                                         └────────┬────────┘ │
└──────────────────────────────────────────────────┼──────────┘
                                                   │
                                          ┌────────▼────────┐
                                          │   KBS Server    │
                                          │  (Host:8080)    │
                                          └─────────────────┘
```

## Prerequisites

### 1. Install Skopeo (Host Machine)

```bash
# Ubuntu/Debian
sudo apt-get install skopeo

# macOS
brew install skopeo

# Or build from source
git clone https://github.com/containers/skopeo
cd skopeo
make bin/skopeo
sudo make install
```

### 2. Start KBS Server (Host Machine)

```bash
# Clone and build KBS
git clone https://github.com/confidential-containers/trustee
cd trustee/kbs
cargo build --release --features sample_only

# Generate admin keys
openssl genpkey -algorithm ed25519 -out kbs-admin.key
openssl pkey -in kbs-admin.key -pubout -out kbs-admin.pub

# Start KBS
./target/release/kbs \
  --insecure-http \
  --auth-public-key kbs-admin.pub \
  --attestation-token-type CoCo
```

KBS will listen on `http://localhost:8080`

### 3. Setup Local OCI Registry (Optional)

For testing, you can use a local registry:

```bash
docker run -d -p 5000:5000 --name registry registry:2
```

## Creating Encrypted Resources

### Encrypt an Algorithm (Python Script)

```bash
# 1. Create a simple algorithm
cat > lin_reg.py << 'EOF'
import pandas as pd
from sklearn.linear_model import LinearRegression
import sys

# Load dataset
data = pd.read_csv(sys.argv[1])
X = data[['feature1', 'feature2']]
y = data['target']

# Train model
model = LinearRegression()
model.fit(X, y)

# Save results
print(f"Coefficients: {model.coef_}")
print(f"Intercept: {model.intercept_}")
EOF

# 2. Create a Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.9-slim
RUN pip install pandas scikit-learn
COPY lin_reg.py /app/algorithm.py
WORKDIR /app
ENTRYPOINT ["python", "algorithm.py"]
EOF

# 3. Build the image
docker build -t localhost:5000/lin-reg-algo:v1.0 .
docker push localhost:5000/lin-reg-algo:v1.0

# 4. Generate encryption key
openssl rand -base64 32 > algo.key

# 5. Store key in KBS
KEY_BASE64=$(cat algo.key | base64 -w0)
curl -X POST http://localhost:8080/kbs/v0/resource/default/key/algo-key \
  -H "Authorization: Bearer $(echo -n '{}' | base64)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@algo.key"

# 6. Encrypt the image using Skopeo
skopeo copy \
  --encryption-key provider:attestation-agent:cc_kbc::kbs:///default/key/algo-key \
  docker://localhost:5000/lin-reg-algo:v1.0 \
  docker://localhost:5000/encrypted-lin-reg:v1.0
```

### Encrypt a Dataset (CSV in OCI Image)

```bash
# 1. Create dataset
cat > iris.csv << 'EOF'
feature1,feature2,target
5.1,3.5,0
4.9,3.0,0
6.2,3.4,1
5.9,3.0,1
EOF

# 2. Create Dockerfile for dataset
cat > Dockerfile.dataset << 'EOF'
FROM scratch
COPY iris.csv /data/iris.csv
EOF

# 3. Build and push
docker build -f Dockerfile.dataset -t localhost:5000/iris-dataset:v1.0 .
docker push localhost:5000/iris-dataset:v1.0

# 4. Generate and store key
openssl rand -base64 32 > dataset.key
curl -X POST http://localhost:8080/kbs/v0/resource/default/key/dataset-key \
  -H "Authorization: Bearer $(echo -n '{}' | base64)" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@dataset.key"

# 5. Encrypt dataset image
skopeo copy \
  --encryption-key provider:attestation-agent:cc_kbc::kbs:///default/key/dataset-key \
  docker://localhost:5000/iris-dataset:v1.0 \
  docker://localhost:5000/encrypted-iris:v1.0
```

## Running a Computation

### 1. Start Manager (Host)

```bash
cd /path/to/cocos-ai
./build/cocos-manager
```

### 2. Start CVMS Test Server (Host)

Get your host IP:
```bash
HOST_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -n1)
```

Start CVMS server:
```bash
HOST=$HOST_IP PORT=7001 ./build/cvms-test \
  -public-key-path ./public.pem \
  -attested-tls-bool false \
  -kbs-url http://$HOST_IP:8080 \
  -algo-type oci-image \
  -algo-source-url docker://localhost:5000/encrypted-lin-reg:v1.0 \
  -algo-kbs-path default/key/algo-key \
  -dataset-type oci-image \
  -dataset-source-url docker://localhost:5000/encrypted-iris:v1.0 \
  -dataset-kbs-path default/key/dataset-key
```

### 3. Create VM via CLI (Host)

```bash
./build/cocos-cli agent create \
  --manager-url http://localhost:7020 \
  --cvms-url http://$HOST_IP:7001
```

The agent will:
1. Receive computation manifest from CVMS
2. Use Skopeo to download encrypted OCI images
3. Skopeo invokes CoCo Keyprovider via ocicrypt
4. CoCo Keyprovider requests decryption key from KBS
5. Attestation Agent generates TEE evidence for KBS
6. KBS validates evidence and returns decryption key
7. Image layers are decrypted and extracted
8. Computation executes with decrypted algorithm and dataset

## Verifying the Setup

### Check CoCo Keyprovider Status (Inside CVM)

```bash
# SSH into CVM or use console
systemctl status coco-keyprovider
journalctl -u coco-keyprovider -f
```

### Check Attestation Agent Status

```bash
systemctl status attestation-agent
journalctl -u attestation-agent -f
```

### Test Skopeo Decryption Manually

```bash
# Inside CVM
export OCICRYPT_KEYPROVIDER_CONFIG=/etc/ocicrypt_keyprovider.conf

skopeo copy \
  --decryption-key provider:attestation-agent:cc_kbc::null \
  docker://localhost:5000/encrypted-lin-reg:v1.0 \
  oci:/tmp/decrypted-algo

# Verify decryption
skopeo inspect oci:/tmp/decrypted-algo | jq -r '.LayersData[].MIMEType'
# Should show: application/vnd.oci.image.layer.v1.tar+gzip
```

## Computation Manifest Format

The CVMS server sends this manifest to the agent:

```json
{
  "computation_id": "1",
  "algorithm": {
    "type": "oci-image",
    "uri": "docker://localhost:5000/encrypted-lin-reg:v1.0",
    "encrypted": true,
    "kbs_resource_path": "default/key/algo-key"
  },
  "datasets": [
    {
      "type": "oci-image",
      "uri": "docker://localhost:5000/encrypted-iris:v1.0",
      "encrypted": true,
      "kbs_resource_path": "default/key/dataset-key"
    }
  ],
  "kbs_url": "http://192.168.100.15:8080"
}
```

## Troubleshooting

### CoCo Keyprovider Not Starting

```bash
# Check logs
journalctl -u coco-keyprovider -n 50

# Verify socket is listening
ss -tlnp | grep 50011

# Check environment
cat /etc/default/coco-keyprovider
```

### Skopeo Decryption Fails

```bash
# Verify ocicrypt config
cat /etc/ocicrypt_keyprovider.conf

# Test keyprovider connection
grpcurl -plaintext 127.0.0.1:50011 list

# Check KBS connectivity from CVM
curl http://HOST_IP:8080/kbs/v0/auth
```

### KBS Returns 401

```bash
# Check KBS logs on host
# Verify attestation evidence format
# Ensure KBS is configured for sample attestation
```

## Differences from Previous Approach

| Aspect | Old (Custom) | New (CoCo Standard) |
|--------|-------------|---------------------|
| **Download** | Custom S3/HTTP clients | Skopeo (OCI standard) |
| **Decryption** | Custom KBS client | CoCo Keyprovider |
| **Attestation** | Direct KBS RCAR | AA → CoCo KP → KBS |
| **Format** | Raw encrypted files | OCI encrypted images |
| **Complexity** | ~2000 lines custom code | Standard CoCo components |

## Benefits

1. **Standards Compliance**: Uses OCI and CoCo standards
2. **Better Tooling**: Leverage Skopeo, Docker, Podman ecosystem
3. **Simplified Code**: Remove custom registry/decryption logic
4. **Proven Solution**: Battle-tested CoCo components
5. **Docker Native**: Works with existing Docker workflows

## Next Steps

- Encrypt your algorithms and datasets as OCI images
- Push to your preferred OCI registry (Docker Hub, GHCR, etc.)
- Update computation manifests to use `oci-image` type
- Test end-to-end flow with encrypted workloads
