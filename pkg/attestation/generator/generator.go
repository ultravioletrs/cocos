// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package generator

import (
	"crypto"

	"github.com/ultravioletrs/cocos/pkg/attestation/corimgen"
)

// Legacy SNP Defaults (re-exported from corimgen)
const (
	SNPDefaultVmpl        = corimgen.SNPDefaultVmpl
	SNPDefaultMeasurement = corimgen.SNPDefaultMeasurement
)

// Legacy TDX Defaults (re-exported from corimgen)
var (
	TDXDefaultMrSeam = corimgen.TDXDefaultMrSeam
	TDXDefaultMrTd   = corimgen.TDXDefaultMrTd
	TDXDefaultRTMRs  = corimgen.TDXDefaultRTMRs
)

// Options defines the configuration for CoRIM generation.
// This is a wrapper around corimgen.Options for backward compatibility.
type Options struct {
	Platform    string        // "snp" or "tdx"
	Measurement string        // Hex-encoded measurement
	Product     string        // SNP processor product name
	SVN         uint64        // Security Version Number
	Policy      uint64        // SNP policy flags
	RTMRs       string        // TDX RTMRs (comma-separated hex)
	MrSeam      string        // TDX MRSEAM (hex)
	HostData    string        // SNP host data (hex)
	LaunchTCB   uint64        // SNP minimum launch TCB
	SigningKey  crypto.Signer // Optional COSE signing key
}

// GenerateCoRIM generates a CoRIM attestation policy using veraison/corim.
// If SigningKey is provided in options, the CoRIM will be signed using COSE_Sign1.
func GenerateCoRIM(opts Options) ([]byte, error) {
	// Convert to corimgen.Options
	corimgenOpts := corimgen.Options{
		Platform:    opts.Platform,
		Measurement: opts.Measurement,
		Product:     opts.Product,
		SVN:         opts.SVN,
		Policy:      opts.Policy,
		RTMRs:       opts.RTMRs,
		MrSeam:      opts.MrSeam,
		HostData:    opts.HostData,
		LaunchTCB:   opts.LaunchTCB,
		SigningKey:  opts.SigningKey,
	}

	return corimgen.GenerateCoRIM(corimgenOpts)
}
