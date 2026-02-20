// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"testing"

	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestFetchTDXAttestationPolicy_Success(t *testing.T) {
	tests := []struct {
		name   string
		config *TDXConfig
	}{
		{
			name: "all fields populated",
			config: &TDXConfig{
				SGXVendorID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				MinTdxSvn:    [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
				MrSeam:       []byte{0x21, 0x22, 0x23, 0x24},
				TdAttributes: [8]byte{0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c},
				Xfam:         [8]byte{0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34},
				MrTd:         []byte{0x35, 0x36, 0x37, 0x38},
				RTMR: [4][]byte{
					{0x41, 0x42, 0x43, 0x44},
					{0x45, 0x46, 0x47, 0x48},
					{0x49, 0x4a, 0x4b, 0x4c},
					{0x4d, 0x4e, 0x4f, 0x50},
				},
			},
		},
		{
			name: "all zeros",
			config: &TDXConfig{
				SGXVendorID:  [16]byte{},
				MinTdxSvn:    [16]byte{},
				MrSeam:       []byte{0},
				TdAttributes: [8]byte{},
				Xfam:         [8]byte{},
				MrTd:         []byte{0},
				RTMR:         [4][]byte{{}, {}, {}, {}},
			},
		},
		{
			name: "empty RTMR slices",
			config: &TDXConfig{
				SGXVendorID:  [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				MinTdxSvn:    [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
				MrSeam:       []byte{0xaa, 0xbb, 0xcc, 0xdd},
				TdAttributes: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Xfam:         [8]byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
				MrTd:         []byte{0xde, 0xad, 0xbe, 0xef},
				RTMR:         [4][]byte{{}, {}, {}, {}},
			},
		},
		{
			name: "partial RTMR",
			config: &TDXConfig{
				SGXVendorID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
				MinTdxSvn:    [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
				MrSeam:       []byte{0x11, 0x22, 0x33, 0x44},
				TdAttributes: [8]byte{0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc},
				Xfam:         [8]byte{0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44},
				MrTd:         []byte{0x55, 0x66, 0x77, 0x88},
				RTMR: [4][]byte{
					{0x01, 0x02, 0x03, 0x04},
					{0x05, 0x06, 0x07, 0x08},
					{0},
					{0},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := FetchTDXAttestationPolicy(tt.config)

			require.NoError(t, err)
			require.NotNil(t, policy)
			assert.Greater(t, len(policy), 0, "policy should not be empty")

			// Verify it's valid JSON
			var jsonCheck map[string]interface{}
			err = json.Unmarshal(policy, &jsonCheck)
			require.NoError(t, err, "policy should be valid JSON")

			// Unmarshal back to protobuf to verify structure
			var parsedConfig ccpb.Config
			err = protojson.Unmarshal(policy, &parsedConfig)
			require.NoError(t, err, "should be able to unmarshal back to protobuf")

			// Verify RootOfTrust settings
			require.NotNil(t, parsedConfig.RootOfTrust)
			assert.True(t, parsedConfig.RootOfTrust.CheckCrl, "CheckCrl should be true")
			assert.True(t, parsedConfig.RootOfTrust.GetCollateral, "GetCollateral should be true")

			// Verify Policy structure
			require.NotNil(t, parsedConfig.Policy)
			require.NotNil(t, parsedConfig.Policy.HeaderPolicy)
			require.NotNil(t, parsedConfig.Policy.TdQuoteBodyPolicy)

			// Verify HeaderPolicy
			assert.Equal(t, tt.config.SGXVendorID[:], parsedConfig.Policy.HeaderPolicy.QeVendorId)

			// Verify TdQuoteBodyPolicy
			assert.Equal(t, tt.config.MinTdxSvn[:], parsedConfig.Policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn)
			assert.Equal(t, tt.config.MrSeam, parsedConfig.Policy.TdQuoteBodyPolicy.MrSeam)
			assert.Equal(t, tt.config.TdAttributes[:], parsedConfig.Policy.TdQuoteBodyPolicy.TdAttributes)
			assert.Equal(t, tt.config.Xfam[:], parsedConfig.Policy.TdQuoteBodyPolicy.Xfam)
			assert.Equal(t, tt.config.MrTd, parsedConfig.Policy.TdQuoteBodyPolicy.MrTd)

			// Verify RTMRs
			assert.Equal(t, len(tt.config.RTMR), len(parsedConfig.Policy.TdQuoteBodyPolicy.Rtmrs))
			for i, rtmr := range tt.config.RTMR {
				assert.Equal(t, rtmr, parsedConfig.Policy.TdQuoteBodyPolicy.Rtmrs[i])
			}
		})
	}
}

func TestFetchTDXAttestationPolicy_NilConfig(t *testing.T) {
	_, err := FetchTDXAttestationPolicy(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrTdxConfigNil.Error(), "error should indicate nil config")
}

func TestFetchTDXAttestationPolicy_OutputFormat(t *testing.T) {
	config := &TDXConfig{
		SGXVendorID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		MinTdxSvn:    [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		MrSeam:       []byte{0x21, 0x22, 0x23, 0x24},
		TdAttributes: [8]byte{0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c},
		Xfam:         [8]byte{0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34},
		MrTd:         []byte{0x35, 0x36, 0x37, 0x38},
		RTMR: [4][]byte{
			{0x41, 0x42, 0x43, 0x44},
			{0x45, 0x46, 0x47, 0x48},
			{0x49, 0x4a, 0x4b, 0x4c},
			{0x4d, 0x4e, 0x4f, 0x50},
		},
	}

	policy, err := FetchTDXAttestationPolicy(config)
	require.NoError(t, err)

	// Verify multiline format with indentation
	policyStr := string(policy)
	assert.Contains(t, policyStr, "\n", "should be multiline")
	assert.Contains(t, policyStr, "  ", "should have indentation")

	// Verify it contains expected keys
	assert.Contains(t, policyStr, "rootOfTrust")
	assert.Contains(t, policyStr, "policy")
	assert.Contains(t, policyStr, "headerPolicy")
	assert.Contains(t, policyStr, "tdQuoteBodyPolicy")
	assert.Contains(t, policyStr, "checkCrl")
	assert.Contains(t, policyStr, "getCollateral")
}

func TestFetchTDXAttestationPolicy_EmptyByteSlices(t *testing.T) {
	config := &TDXConfig{
		SGXVendorID:  [16]byte{},
		MinTdxSvn:    [16]byte{},
		MrSeam:       nil,
		TdAttributes: [8]byte{},
		Xfam:         [8]byte{},
		MrTd:         nil,
		RTMR:         [4][]byte{nil, nil, nil, nil},
	}

	policy, err := FetchTDXAttestationPolicy(config)
	require.NoError(t, err)

	var parsedConfig ccpb.Config
	err = protojson.Unmarshal(policy, &parsedConfig)
	require.NoError(t, err)

	// Verify nil slices are handled correctly
	assert.NotNil(t, parsedConfig.Policy.HeaderPolicy.QeVendorId)
	assert.NotNil(t, parsedConfig.Policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn)
	assert.NotNil(t, parsedConfig.Policy.TdQuoteBodyPolicy.TdAttributes)
	assert.NotNil(t, parsedConfig.Policy.TdQuoteBodyPolicy.Xfam)
}
