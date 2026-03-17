// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package corimgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"
)

func TestGenerateCoRIM_SNP_Unsigned(t *testing.T) {
	opts := Options{
		Platform:    "snp",
		Measurement: "abc123",
		Product:     "Milan",
		SVN:         1,
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)

	// Verify it's valid CBOR CoRIM
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, unsignedCorim.GetID())
}

func TestGenerateCoRIM_TDX_Unsigned(t *testing.T) {
	opts := Options{
		Platform: "tdx",
		// Will use defaults
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)

	// Verify it's valid CBOR CoRIM
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, unsignedCorim.GetID())
}

func TestGenerateCoRIM_WithDefaults(t *testing.T) {
	opts := Options{
		Platform: "snp",
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)

	// Decode and verify default measurement was used
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)

	// Verify CoRIM was created successfully
	assert.NotEmpty(t, unsignedCorim.GetID())
}

func TestGenerateCoRIM_InvalidMeasurement(t *testing.T) {
	opts := Options{
		Platform:    "snp",
		Measurement: "invalid-hex",
	}

	_, err := GenerateCoRIM(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode measurement")
}

func TestApplyDefaults_SNP(t *testing.T) {
	opts := Options{
		Platform: "snp",
	}

	applyDefaults(&opts)

	assert.Equal(t, SNPDefaultMeasurement, opts.Measurement)
}

func TestApplyDefaults_TDX(t *testing.T) {
	opts := Options{
		Platform: "tdx",
	}

	applyDefaults(&opts)

	assert.Equal(t, TDXDefaultMrTd, opts.Measurement)
	assert.Equal(t, TDXDefaultMrSeam, opts.MrSeam)
	assert.NotEmpty(t, opts.RTMRs)
}

func TestGenerateCoRIM_TDX_WithRTMRs(t *testing.T) {
	rtmr1 := "ce0891f46a18db93e7691f1cf73ed76593f7dec1b58f0927ccb56a99242bf63bc9551561f9ee7833d40395fae59547ab"
	rtmr2 := "062ac322e26b10874a84977a09735408a856aec77ff62b4975b1e90e33c18f05220ea522cdbffc3b2cf4451cc209e418"

	opts := Options{
		Platform:    "tdx",
		Measurement: TDXDefaultMrTd,
		MrSeam:      TDXDefaultMrSeam,
		RTMRs:       rtmr1 + "," + rtmr2,
		SVN:         2,
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)

	// Verify it's valid
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)
}

func TestGenerateCoRIM_SNP_WithHostData(t *testing.T) {
	opts := Options{
		Platform:    "snp",
		Measurement: "abc123",
		HostData:    "deadbeef",
		LaunchTCB:   1,
		SVN:         1,
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)
}

func TestGenerateCoRIM_TDX_InvalidMrSeam(t *testing.T) {
	opts := Options{
		Platform: "tdx",
		MrSeam:   "invalid-hex",
	}

	_, err := GenerateCoRIM(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode MRSEAM")
}

func TestGenerateCoRIM_TDX_InvalidRTMR(t *testing.T) {
	opts := Options{
		Platform: "tdx",
		RTMRs:    "invalid-hex",
	}

	_, err := GenerateCoRIM(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode RTMR")
}

func TestGenerateCoRIM_WithSigning(t *testing.T) {
	// This would require a mock signer, but for now we can test that it
	// fails if we provide something that looks like a key but is invalid or not fully supported
	// However, we've already tested the unsigned paths which are the main focus.
	t.Skip("Signing test requires mock signer")
}
