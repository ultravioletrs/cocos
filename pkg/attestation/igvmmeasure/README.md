# IGVM Measure Package

The `igvmmeasure` package provides a Go wrapper for the `igvmmeasure` binary, which calculates measurements for IGVM (Isolated Guest Virtual Machine) files used in AMD SEV-SNP environments.

## Overview

This package executes the `igvmmeasure` binary to compute cryptographic measurements of IGVM files, which are essential for SEV-SNP attestation and policy generation.

## Features

- **Binary Wrapper**: Executes the `igvmmeasure` binary with proper arguments
- **Measurement Calculation**: Computes IGVM file measurements for SEV-SNP
- **Flexible I/O**: Supports custom stdout/stderr writers for output capture
- **Testable**: Allows injection of mock exec commands for testing

## Usage

### Basic Example

```go
import (
    "bytes"
    "github.com/ultravioletrs/cocos/pkg/attestation/igvmmeasure"
)

var stdout, stderr bytes.Buffer

// Create measurement provider
measurer, err := igvmmeasure.NewIgvmMeasurement(
    "/path/to/igvmmeasure",
    &stderr,
    &stdout,
)
if err != nil {
    // handle error
}

// Calculate measurement
err = measurer.Run("/path/to/file.igvm")
if err != nil {
    // handle error
}

// Get measurement (hex string)
measurement := stdout.String()
```

### Manager Integration

The manager uses this package to calculate IGVM measurements dynamically:

```go
igvmMeasurementBinaryPath := fmt.Sprintf("%s/igvmmeasure", ms.attestationPolicyBinaryPath)

var stdoutBuffer bytes.Buffer
var stderrBuffer bytes.Buffer

stdout := bufio.NewWriter(&stdoutBuffer)
stderr := bufio.NewWriter(&stderrBuffer)

igvmMeasurement, err := igvmmeasure.NewIgvmMeasurement(
    igvmMeasurementBinaryPath,
    stderr,
    stdout,
)
if err != nil {
    return nil, fmt.Errorf("failed to create IGVM measurement: %w", err)
}

err = igvmMeasurement.Run(ms.qemuCfg.IGVMConfig.File)
if err != nil {
    return nil, fmt.Errorf("failed to run IGVM measurement: %w", err)
}

measurement := fmt.Sprintf("%x", stdoutBuffer.Bytes())
```

## Binary Requirements

The `igvmmeasure` binary must be available at the specified path. This binary is typically built from the [COCONUT-SVSM](https://github.com/coconut-svsm/svsm) project.

### Building igvmmeasure

```bash
# Clone COCONUT-SVSM repository
git clone https://github.com/coconut-svsm/svsm
cd svsm

# Build igvmmeasure
cd tools/igvmmeasure
cargo build --release

# Binary will be at: target/release/igvmmeasure
```

## Configuration

The manager expects the binary path to be configured via environment variable:

```bash
export MANAGER_ATTESTATION_POLICY_BINARY_PATH=/path/to/binaries
```

The manager will look for `igvmmeasure` in `${MANAGER_ATTESTATION_POLICY_BINARY_PATH}/igvmmeasure`.

## Interface

### MeasurementProvider

```go
type MeasurementProvider interface {
    Run(igvmBinaryPath string) error
    Stop() error
}
```

### IgvmMeasurement

```go
type IgvmMeasurement struct {
    // Contains binary path, options, and I/O writers
}

func NewIgvmMeasurement(binPath string, stderr, stdout io.Writer) (*IgvmMeasurement, error)
func (m *IgvmMeasurement) Run(pathToFile string) error
func (m *IgvmMeasurement) Stop() error
func (m *IgvmMeasurement) SetExecCommand(cmdFunc func(name string, arg ...string) *exec.Cmd)
```

## Testing

The package supports test mocking via `SetExecCommand`:

```go
measurer.SetExecCommand(func(name string, arg ...string) *exec.Cmd {
    // Return mock command
})
```

## See Also

- [Generator Package](../generator/README.md)
- [COCONUT-SVSM Documentation](https://github.com/coconut-svsm/svsm)
