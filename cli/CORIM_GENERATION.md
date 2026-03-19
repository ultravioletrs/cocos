# CoRIM Generation CLI Commands

This document describes the CLI commands for generating CoRIM (Concise Reference Integrity Manifest) attestation policies.

## Overview

The `cocos-cli policy create-corim` command provides subcommands for generating CoRIM policies for different platforms:
- **azure**: Generate from Azure Attestation Token
- **gcp**: Generate from GCP endorsements
- **snp**: Generate for AMD SEV-SNP (direct host generation)
- **tdx**: Generate for Intel TDX (direct host generation)

## Commands

### Azure SEV-SNP

Generate CoRIM from an Azure Attestation Token (JWT).

```bash
cocos-cli policy create-corim azure --token <path-to-token> [--product <product>]
```

**Flags:**
- `--token` (required): Path to file containing Azure Attestation Token (JWT)
- `--product` (optional): Processor product name (default: "Milan")

**Example:**
```bash
cocos-cli policy create-corim azure \
  --token /path/to/token.jwt \
  --product Milan \
  > azure-policy.corim
```

### GCP SEV-SNP

Generate CoRIM from GCP SEV-SNP measurement and endorsements.

```bash
cocos-cli policy create-corim gcp --measurement <hex> [--vcpu <num>]
```

**Flags:**
- `--measurement` (required): 384-bit measurement hex string
- `--vcpu` (optional): vCPU number (default: 0)

**Example:**
```bash
cocos-cli policy create-corim gcp \
  --measurement abc123... \
  --vcpu 0 \
  > gcp-policy.corim
```

### SEV-SNP (Direct Host)

Generate CoRIM for AMD SEV-SNP platform directly on the host.

```bash
cocos-cli policy create-corim snp [flags]
```

**Flags:**
- `--measurement` (optional): Measurement/Launch Digest (hex string, defaults to zero if not provided)
- `--policy` (optional): SNP policy flags (default: 0)
- `--svn` (optional): Security Version Number/TCB (default: 0)
- `--product` (optional): Processor product name (default: "Milan")
- `--host-data` (optional): Host data (hex string)
- `--launch-tcb` (optional): Minimum launch TCB (default: 0)
- `--output` (optional): Output file path (default: stdout)

**Examples:**

Generate with defaults (zeroed measurement):
```bash
cocos-cli policy create-corim snp \
  --product Milan \
  --output snp-policy.corim
```

Generate with custom measurement:
```bash
cocos-cli policy create-corim snp \
  --measurement abc123def456... \
  --product Genoa \
  --svn 1 \
  --policy 0x30000 \
  --output snp-policy.corim
```

Generate with host data and launch TCB:
```bash
cocos-cli policy create-corim snp \
  --measurement abc123... \
  --host-data deadbeef \
  --launch-tcb 1 \
  --output snp-policy.corim
```

### TDX (Direct Host)

Generate CoRIM for Intel TDX platform directly on the host.

```bash
cocos-cli policy create-corim tdx [flags]
```

**Flags:**
- `--measurement` (optional): MRTD measurement (hex string, uses default if not provided)
- `--svn` (optional): Security Version Number (default: 0)
- `--rtmrs` (optional): Comma-separated RTMRs (hex)
- `--mr-seam` (optional): MRSEAM (hex)
- `--output` (optional): Output file path (default: stdout)

**Examples:**

Generate with defaults (matches legacy script behavior):
```bash
cocos-cli policy create-corim tdx \
  --output tdx-policy.corim
```

Generate with custom values:
```bash
cocos-cli policy create-corim tdx \
  --measurement abc123def456... \
  --rtmrs rtmr0,rtmr1,rtmr2,rtmr3 \
  --mr-seam 789abc... \
  --svn 2 \
  --output tdx-policy.corim
```

## Signing CoRIMs

CoRIMs can be signed using a private key (COSE_Sign1). The generated output will be a COSE-wrapped CoRIM in CBOR format.

### Prerequisite: Generate Signing Key

You will need an EC private key (P-256) in PEM format. You can generate one using `openssl`:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
```

### Signing with CLI

Use the `--signing-key` flag to sign the CoRIM during generation.

**SNP Example:**
```bash
cocos-cli policy create-corim snp \
  --product Milan \
  --signing-key private-key.pem \
  --output signed-snp.corim
```

**TDX Example:**
```bash
cocos-cli policy create-corim tdx \
  --signing-key private-key.pem \
  --output signed-tdx.corim
```

### Verification

The output file is a standard COSE_Sign1 message containing the CoRIM. It can be verified using any tool that supports COSE and CoRIM verification, such as the [veraison/corim](https://github.com/veraison/corim) library.

## Output Format

All commands output CoRIM in CBOR (Concise Binary Object Representation) format. By default, output is written to stdout, allowing for piping:

```bash
# Pipe to file
cocos-cli policy create-corim snp --product Milan > policy.corim

# Pipe to another command
cocos-cli policy create-corim tdx | base64

# Use --output flag
cocos-cli policy create-corim snp --product Milan --output policy.corim
```

## Integration with Manager

The manager service can dynamically generate CoRIM policies using the same underlying generator package. When `FetchAttestationPolicy` is called:

1. For SNP: Calculates IGVM measurement using the `igvmmeasure` binary
2. Extracts host data and launch TCB from VM configuration
3. Generates CoRIM using the `generator` package
4. Returns CBOR-encoded CoRIM

## See Also

- [Generator Package Documentation](../pkg/attestation/generator/README.md)
- [IGVM Measure Package Documentation](../pkg/attestation/igvmmeasure/README.md)
- [Manager README](../manager/README.md)
