# CoRIM Generator (veraison/corim)

This package provides CoRIM (Concise Reference Integrity Manifest) generation using the standard [veraison/corim](https://github.com/veraison/corim) library.

## Overview

The `corimgen` package generates CoRIM attestation policies for confidential computing platforms (SNP and TDX) using the veraison/corim library, which provides:
- Standard-compliant CoRIM/CoMID structures per RFC 9393
- Built-in COSE signing and verification
- Ecosystem compatibility with Veraison attestation services

## Features

- **SNP Support**: Generate CoRIM for AMD SEV-SNP with measurements, SVN, and product information
- **TDX Support**: Generate CoRIM for Intel TDX with MRTD, MRSEAM, and RTMRs
- **COSE Signing**: Optional COSE_Sign1 signing with crypto.Signer keys
- **Defaults**: Sensible defaults for testing and development

## Usage

### Basic Usage (Unsigned)

```go
import "github.com/ultravioletrs/cocos/pkg/attestation/corimgen"

opts := corimgen.Options{
    Platform:    "snp",
    Measurement: "abc123...", // hex-encoded
    Product:     "Milan",
    SVN:         1,
}

corimBytes, err := corimgen.GenerateCoRIM(opts)
```

### With Signing

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    
    "github.com/ultravioletrs/cocos/pkg/attestation/corimgen"
)

// Generate signing key
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

opts := corimgen.Options{
    Platform:    "snp",
    Measurement: "abc123...",
    SVN:         1,
    SigningKey:  privateKey, // COSE signing
}

signedCorimBytes, err := corimgen.GenerateCoRIM(opts)
```

### TDX with RTMRs

```go
opts := corimgen.Options{
    Platform:    "tdx",
    Measurement: "91eb2b44...", // MRTD
    MrSeam:      "5b38e33a...", // MRSEAM
    RTMRs:       "ce0891f4...,062ac322...,5fd86e8c...,00000000...", // comma-separated
    SVN:         2,
}

corimBytes, err := corimgen.GenerateCoRIM(opts)
```

## Options

| Field | Type | Description |
|-------|------|-------------|
| `Platform` | string | Platform type: "snp" or "tdx" |
| `Measurement` | string | Hex-encoded measurement (MRTD for TDX, measurement for SNP) |
| `Product` | string | SNP processor product name (e.g., "Milan", "Genoa") |
| `SVN` | uint64 | Security Version Number |
| `Policy` | uint64 | SNP policy flags |
| `RTMRs` | string | TDX Runtime Measurement Registers (comma-separated hex) |
| `MrSeam` | string | TDX SEAM module measurement (hex) |
| `HostData` | string | SNP host data (hex) |
| `LaunchTCB` | uint64 | SNP minimum launch TCB |
| `SigningKey` | crypto.Signer | Optional COSE signing key (ES256) |

## Defaults

The package provides sensible defaults for testing:

### SNP
- `SNPDefaultMeasurement`: 48-byte zero measurement
- `SNPDefaultVmpl`: VMPL level 2

### TDX
- `TDXDefaultMrTd`: Default MRTD value
- `TDXDefaultMrSeam`: Default MRSEAM value
- `TDXDefaultRTMRs`: Default RTMR values (4 registers)

## Implementation Details

### CoRIM Structure

Generated CoRIM contains:
- **CoRIM ID**: Unique identifier (`platform-corim-{uuid}`)
- **CoMID Tags**: One or more CoMID tags with:
  - **Tag Identity**: Unique tag ID and version
  - **Environment**: Platform class (UUID) and optional instance (product)
  - **Reference Values**: Measurements with:
    - **Key**: UUID identifier for each measurement
    - **Digests**: SHA-256 hash of measurement
    - **SVN**: Security version number (if specified)

### Signing

When `SigningKey` is provided:
1. Creates unsigned CoRIM
2. Wraps in COSE_Sign1 message
3. Signs with ES256 algorithm (ECDSA P-256)
4. Returns signed CBOR bytes

### Verification

To verify a signed CoRIM:
```go
import (
    "crypto/ecdsa"
    "github.com/veraison/corim/corim"
)

var signedCorim corim.SignedCorim
err := signedCorim.FromCOSE(signedBytes)

publicKey := privateKey.Public().(*ecdsa.PublicKey)
err = signedCorim.Verify(publicKey)
```

## Testing

Run tests:
```bash
go test ./pkg/attestation/corimgen/... -v
```

## Integration

This package is used by:
- `pkg/attestation/generator` - Backward-compatible wrapper
- `cli` - CoRIM generation commands
- `manager` - Dynamic CoRIM policy generation

## References

- [RFC 9393 - CoRIM](https://datatracker.ietf.org/doc/rfc9393/)
- [veraison/corim](https://github.com/veraison/corim)
- [COSE (RFC 9052)](https://datatracker.ietf.org/doc/rfc9052/)
