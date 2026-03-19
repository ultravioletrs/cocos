# CoRIM Generator Package

The `generator` package provides a unified interface for generating CoRIM (Concise Reference Integrity Manifest) attestation policies for different TEE platforms.

## Overview

This package consolidates CoRIM generation logic for SNP and TDX platforms, providing consistent defaults and behavior that matches legacy attestation policy generation scripts.

## Features

- **Platform Support**: SNP (AMD SEV-SNP) and TDX (Intel TDX)
- **Legacy Defaults**: Maintains compatibility with legacy Rust SNP and Go TDX policy scripts
- **Flexible Configuration**: Supports custom measurements, policies, and platform-specific parameters
- **CBOR Output**: Generates CoRIM in CBOR format for standardized attestation

## Usage

### Basic Example

```go
import "github.com/ultravioletrs/cocos/pkg/attestation/generator"

// Generate SNP CoRIM with defaults
opts := generator.Options{
    Platform: "snp",
    Product:  "Milan",
}
corimBytes, err := generator.GenerateCoRIM(opts)
if err != nil {
    // handle error
}
```

### SNP with Custom Values

```go
opts := generator.Options{
    Platform:    "snp",
    Measurement: "abc123...", // hex string
    Product:     "Genoa",
    SVN:         1,
    Policy:      0x30000,
    HostData:    "deadbeef", // hex string
    LaunchTCB:   1,
}
corimBytes, err := generator.GenerateCoRIM(opts)
```

### TDX with Custom Values

```go
opts := generator.Options{
    Platform:    "tdx",
    Measurement: "def456...", // MRTD hex string
    SVN:         2,
    RTMRs:       "rtmr0,rtmr1,rtmr2,rtmr3", // comma-separated hex
    MrSeam:      "789abc...", // hex string
}
corimBytes, err := generator.GenerateCoRIM(opts)
```

## Options

### Common Fields
- `Platform` (string): Platform type - "snp" or "tdx"
- `Measurement` (string): Hex-encoded measurement (defaults provided if empty)
- `SVN` (uint64): Security Version Number

### SNP-Specific Fields
- `Product` (string): Processor product name (e.g., "Milan", "Genoa")
- `Policy` (uint64): SNP policy flags
- `HostData` (string): Hex-encoded host data
- `LaunchTCB` (uint64): Minimum launch TCB version

### TDX-Specific Fields
- `RTMRs` (string): Comma-separated hex-encoded RTMRs
- `MrSeam` (string): Hex-encoded MRSEAM value

## Default Values

### SNP Defaults
- Measurement: 48 bytes of zeros (if not provided)
- Product: "Milan"
- SVN: 0
- Policy: 0

### TDX Defaults
- Measurement (MRTD): `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- MRSEAM: `2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656`
- RTMRs: Four 48-byte zero values
- SVN: 0

## Integration

This package is used by:
- **CLI**: `cocos-cli policy create-corim snp/tdx` commands
- **Manager**: Dynamic CoRIM generation in `FetchAttestationPolicy`
- **Scripts**: `scripts/corim_gen` standalone tool

## See Also

- [CoRIM Package](../corim/README.md)
- [IGVM Measure Package](../igvmmeasure/README.md)
