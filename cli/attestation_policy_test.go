// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
)

func TestChangeAttestationConfiguration(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "attestation_policy.json")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	initialConfig := attestation.Config{Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}, PcrConfig: &attestation.PcrConfig{}}

	initialJSON, err := json.Marshal(initialConfig)
	require.NoError(t, err)
	err = os.WriteFile(tmpfile.Name(), initialJSON, 0o644)
	require.NoError(t, err)

	tests := []struct {
		name           string
		base64Data     string
		expectedLength int
		field          fieldType
		expectError    bool
		errorType      error
	}{
		{
			name:           "Valid Measurement",
			base64Data:     base64.StdEncoding.EncodeToString(make([]byte, measurementLength)),
			expectedLength: measurementLength,
			field:          measurementField,
			expectError:    false,
		},
		{
			name:           "Valid Host Data",
			base64Data:     base64.StdEncoding.EncodeToString(make([]byte, hostDataLength)),
			expectedLength: hostDataLength,
			field:          hostDataField,
			expectError:    false,
		},
		{
			name:           "Invalid Base64",
			base64Data:     "Invalid Base64",
			expectedLength: measurementLength,
			field:          measurementField,
			expectError:    true,
			errorType:      errDecode,
		},
		{
			name:           "Invalid Data Length",
			base64Data:     base64.StdEncoding.EncodeToString(make([]byte, measurementLength-1)),
			expectedLength: measurementLength,
			field:          measurementField,
			expectError:    true,
			errorType:      errDataLength,
		},
		{
			name:           "Invalid Field Type",
			base64Data:     base64.StdEncoding.EncodeToString(make([]byte, measurementLength)),
			expectedLength: measurementLength,
			field:          fieldType(999),
			expectError:    true,
			errorType:      errAttestationPolicyField,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := changeAttestationConfiguration(tmpfile.Name(), tt.base64Data, tt.expectedLength, tt.field)

			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.errorType)
			} else {
				assert.NoError(t, err)

				content, err := os.ReadFile(tmpfile.Name())
				require.NoError(t, err)

				ap := attestation.Config{Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}, PcrConfig: &attestation.PcrConfig{}}
				err = vtpm.ReadPolicyFromByte(content, &ap)
				require.NoError(t, err)

				decodedData, _ := base64.StdEncoding.DecodeString(tt.base64Data)
				if tt.field == measurementField {
					assert.Equal(t, decodedData, ap.Config.Policy.Measurement)
				} else if tt.field == hostDataField {
					assert.Equal(t, decodedData, ap.Config.Policy.HostData)
				}
			}
		})
	}
}

func TestNewAttestationPolicyCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewAttestationPolicyCmd()

	assert.Equal(t, "policy [command]", cmd.Use)
	assert.Equal(t, "Change attestation policy", cmd.Short)
	assert.NotNil(t, cmd.Run)
}

func TestNewAddMeasurementCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewAddMeasurementCmd()

	assert.Equal(t, "measurement", cmd.Use)
	assert.Equal(t, "Add measurement to the attestation policy file. The value should be in base64. The second parameter is attestation_policy.json file", cmd.Short)
	assert.Equal(t, "measurement <measurement> <attestation_policy.json>", cmd.Example)
	assert.NotNil(t, cmd.Run)
}

func TestNewAddHostDataCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewAddHostDataCmd()

	assert.Equal(t, "hostdata", cmd.Use)
	assert.Equal(t, "Add host data to the attestation policy file. The value should be in base64. The second parameter is attestation_policy.json file", cmd.Short)
	assert.Equal(t, "hostdata <host-data> <attestation_policy.json>", cmd.Example)
	assert.NotNil(t, cmd.Run)
}
