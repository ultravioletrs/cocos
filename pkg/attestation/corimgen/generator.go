// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package corimgen

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"
)

// Legacy SNP Defaults
const (
	SNPDefaultVmpl        = 2
	SNPDefaultMeasurement = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // 48 bytes
)

// Legacy TDX Defaults
var (
	TDXDefaultMrSeam = "5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c1"
	TDXDefaultMrTd   = "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7"
	TDXDefaultRTMRs  = []string{
		"ce0891f46a18db93e7691f1cf73ed76593f7dec1b58f0927ccb56a99242bf63bc9551561f9ee7833d40395fae59547ab",
		"062ac322e26b10874a84977a09735408a856aec77ff62b4975b1e90e33c18f05220ea522cdbffc3b2cf4451cc209e418",
		"5fd86e8c3d5e45386f1ed0852de7e83ae1b774ee4366bd5213c9890e8e3ac8fad3f7e690891d37f7c81ac20a445cc0ff",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}
)

// Options defines the configuration for CoRIM generation.
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
// If SigningKey is provided, the CoRIM will be signed using COSE_Sign1.
func GenerateCoRIM(opts Options) ([]byte, error) {
	// Apply defaults
	applyDefaults(&opts)

	// Create CoMID
	comidObj, err := createCoMID(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create CoMID: %w", err)
	}

	// Create unsigned CoRIM
	unsignedCorim := corim.NewUnsignedCorim()
	unsignedCorim.SetID(opts.Platform + "-corim-" + uuid.New().String())
	unsignedCorim.AddComid(*comidObj)

	// If no signing key, return unsigned CoRIM
	if opts.SigningKey == nil {
		return unsignedCorim.ToCBOR()
	}

	// Sign the CoRIM
	signedCorim := &corim.SignedCorim{}
	signedCorim.UnsignedCorim = *unsignedCorim

	// Create COSE signer (use ES256 for ECDSA keys)
	signer, err := cose.NewSigner(cose.AlgorithmES256, opts.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE signer: %w", err)
	}

	// Sign the CoRIM - Sign() returns the signed CBOR bytes
	signedCBOR, err := signedCorim.Sign(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CoRIM: %w", err)
	}

	return signedCBOR, nil
}

// applyDefaults applies platform-specific defaults to options.
func applyDefaults(opts *Options) {
	if opts.Platform == "snp" {
		if opts.Measurement == "" {
			opts.Measurement = SNPDefaultMeasurement
		}
	} else if opts.Platform == "tdx" {
		if opts.Measurement == "" {
			opts.Measurement = TDXDefaultMrTd
		}
		if opts.MrSeam == "" {
			opts.MrSeam = TDXDefaultMrSeam
		}
		if opts.RTMRs == "" {
			opts.RTMRs = strings.Join(TDXDefaultRTMRs, ",")
		}
	}
}

// createCoMID creates a CoMID object for the given platform.
func createCoMID(opts Options) (*comid.Comid, error) {
	comidObj := comid.NewComid()

	// Set tag identity
	tagID := opts.Platform + "-tag-" + uuid.New().String()
	comidObj.SetTagIdentity(tagID, 0)

	// Create reference value with environment and measurements
	refVal, err := createReferenceValue(opts)
	if err != nil {
		return nil, err
	}

	comidObj.AddReferenceValue(*refVal)

	return comidObj, nil
}

// createReferenceValue creates a reference value triple for the platform.
func createReferenceValue(opts Options) (*comid.ReferenceValue, error) {
	refVal := &comid.ReferenceValue{}

	// Create environment
	env := comid.Environment{}

	// Set class (platform identifier) - convert google UUID to comid UUID
	googleUUID := uuid.New()
	classUUID := comid.NewClassUUID(comid.UUID(googleUUID))
	env.Class = classUUID

	// Add instance if product specified (SNP) - use UUID based on product name
	if opts.Product != "" {
		// Create a deterministic UUID from the product name
		productUUID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(opts.Product))
		instance, err := comid.NewUUIDInstance(comid.UUID(productUUID))
		if err != nil {
			return nil, fmt.Errorf("failed to create instance: %w", err)
		}
		env.Instance = instance
	}

	refVal.Environment = env

	// Decode main measurement
	measBytes, err := hex.DecodeString(opts.Measurement)
	if err != nil {
		return nil, fmt.Errorf("failed to decode measurement: %w", err)
	}

	// Create main measurement with UUID key
	measUUID := uuid.New()
	mval, err := comid.NewUUIDMeasurement(comid.UUID(measUUID))
	if err != nil {
		return nil, fmt.Errorf("failed to create measurement: %w", err)
	}

	// Add digest with SHA-256 algorithm (algID = 1)
	mval.AddDigest(1, measBytes)

	// Add SVN if specified
	if opts.SVN > 0 {
		mval.SetSVN(opts.SVN)
	}

	// Initialize measurements slice
	refVal.Measurements = comid.Measurements{*mval}

	// Platform-specific additions
	if opts.Platform == "tdx" {
		// Add MRSEAM
		if opts.MrSeam != "" {
			mrSeamBytes, err := hex.DecodeString(opts.MrSeam)
			if err != nil {
				return nil, fmt.Errorf("failed to decode MRSEAM: %w", err)
			}
			seamUUID := uuid.New()
			seamMval, err := comid.NewUUIDMeasurement(comid.UUID(seamUUID))
			if err != nil {
				return nil, fmt.Errorf("failed to create MRSEAM measurement: %w", err)
			}
			seamMval.AddDigest(1, mrSeamBytes)
			refVal.Measurements = append(refVal.Measurements, *seamMval)
		}

		// Add RTMRs
		if opts.RTMRs != "" {
			for _, rtmr := range strings.Split(opts.RTMRs, ",") {
				rtmrBytes, err := hex.DecodeString(strings.TrimSpace(rtmr))
				if err != nil {
					return nil, fmt.Errorf("failed to decode RTMR: %w", err)
				}
				rtmrUUID := uuid.New()
				rtmrMval, err := comid.NewUUIDMeasurement(comid.UUID(rtmrUUID))
				if err != nil {
					return nil, fmt.Errorf("failed to create RTMR measurement: %w", err)
				}
				rtmrMval.AddDigest(1, rtmrBytes)
				refVal.Measurements = append(refVal.Measurements, *rtmrMval)
			}
		}
	}

	return refVal, nil
}
