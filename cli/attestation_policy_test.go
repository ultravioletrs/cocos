// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"encoding/base64"
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

	initialJSON, err := vtpm.ConvertPolicyToJSON(&initialConfig)
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

func TestChangeAttestationConfigurationFileErrors(t *testing.T) {
	t.Run("File Not Found", func(t *testing.T) {
		err := changeAttestationConfiguration("nonexistent.json", base64.StdEncoding.EncodeToString(make([]byte, measurementLength)), measurementLength, measurementField)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error while reading the attestation policy file")
	})

	t.Run("Invalid JSON Content", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "invalid.json")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte("invalid json"), 0o644)
		require.NoError(t, err)

		err = changeAttestationConfiguration(tmpfile.Name(), base64.StdEncoding.EncodeToString(make([]byte, measurementLength)), measurementLength, measurementField)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal json")
	})
}

func TestNewGCPAttestationPolicy(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewGCPAttestationPolicy()

	assert.Equal(t, "gcp", cmd.Use)
	assert.Equal(t, "Get attestation policy for GCP CVM", cmd.Short)
	assert.Equal(t, "gcp <bin_vtmp_attestation_report_file> <vcpu_count>", cmd.Example)
	assert.NotNil(t, cmd.Run)

	t.Run("File Not Found", func(t *testing.T) {
		cmd.SetArgs([]string{"nonexistent.bin", "4"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error reading attestation report file")
		assert.Contains(t, output, "❌")
	})

	t.Run("Invalid vCPU Count", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "attestation.bin")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte("dummy content"), 0o644)
		require.NoError(t, err)

		cmd.SetArgs([]string{tmpfile.Name(), "invalid"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error converting vCPU count to integer")
		assert.Contains(t, output, "❌")
	})

	t.Run("Invalid Attestation Data", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "attestation.bin")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte("invalid protobuf data"), 0o644)
		require.NoError(t, err)

		cmd.SetArgs([]string{tmpfile.Name(), "4"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error unmarshaling attestation report")
		assert.Contains(t, output, "❌")
	})
}

func TestNewDownloadGCPOvmfFile(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewDownloadGCPOvmfFile()

	assert.Equal(t, "download", cmd.Use)
	assert.Equal(t, "Download GCP OVMF file", cmd.Short)
	assert.Equal(t, "download <bin_vtmp_attestation_report_file>", cmd.Example)
	assert.NotNil(t, cmd.Run)

	t.Run("File Not Found", func(t *testing.T) {
		cmd.SetArgs([]string{"nonexistent.bin"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error reading attestation report file")
		assert.Contains(t, output, "❌")
	})

	t.Run("Invalid Attestation Data", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "attestation.bin")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte("invalid protobuf data"), 0o644)
		require.NoError(t, err)

		cmd.SetArgs([]string{tmpfile.Name()})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error unmarshaling attestation report")
		assert.Contains(t, output, "❌")
	})
}

func TestNewAzureAttestationPolicy(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewAzureAttestationPolicy()

	assert.Equal(t, "azure", cmd.Use)
	assert.Equal(t, "Get attestation policy for Azure CVM", cmd.Short)
	assert.Equal(t, "azure <azure_maa_token_file> <product_name>", cmd.Example)
	assert.NotNil(t, cmd.Run)

	flag := cmd.Flags().Lookup("policy")
	assert.NotNil(t, flag)
	assert.Equal(t, "Policy of the guest CVM", flag.Usage)

	t.Run("File Not Found", func(t *testing.T) {
		cmd.SetArgs([]string{"nonexistent.token", "test-product"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error reading attestation report file")
		assert.Contains(t, output, "❌")
	})

	t.Run("Valid Token File", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "token.maa")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte("dummy.token.content"), 0o644)
		require.NoError(t, err)

		defer os.Remove("attestation_policy.json")

		cmd.SetArgs([]string{tmpfile.Name(), "test-product"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("Custom Policy Flag", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "token.maa")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		err = os.WriteFile(tmpfile.Name(), []byte("dummy.token.content"), 0o644)
		require.NoError(t, err)

		cmd.SetArgs([]string{"--policy", "123456", tmpfile.Name(), "test-product"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		assert.NoError(t, err)

		flag := cmd.Flags().Lookup("policy")
		assert.NotNil(t, flag)
		assert.Equal(t, "123456", flag.Value.String())
	})
}

func TestCommandErrorHandling(t *testing.T) {
	cli := &CLI{}

	t.Run("Measurement Command Error", func(t *testing.T) {
		cmd := cli.NewAddMeasurementCmd()
		cmd.SetArgs([]string{"invalid-base64", "nonexistent.json"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error could not change measurement data")
		assert.Contains(t, output, "❌")
	})

	t.Run("Host Data Command Error", func(t *testing.T) {
		cmd := cli.NewAddHostDataCmd()
		cmd.SetArgs([]string{"invalid-base64", "nonexistent.json"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "Error could not change host data")
		assert.Contains(t, output, "❌")
	})
}

func TestExtendWithManifestHandling(t *testing.T) {
	cli := &CLI{}

	t.Run("Invalid policy file", func(t *testing.T) {
		cmd := cli.NewExtendWithManifestCmd()
		cmd.SetArgs([]string{"nonexistent.policy.json", "nonexistent.manifest.json"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "error while reading the attestation policy file")
		assert.Contains(t, output, "❌")
	})

	t.Run("Invalid manifest file", func(t *testing.T) {
		cmd := cli.NewExtendWithManifestCmd()
		cmd.SetArgs([]string{"../scripts/attestation_policy/attestation_policy.json", "nonexistent.manifest.json"})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		assert.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "error while reading manifest file")
		assert.Contains(t, output, "❌")
	})

	t.Run("Valid file paths", func(t *testing.T) {
		fileContent := `{
		  "id": "1",
		  "name": "sample computation",
		  "description": "sample description",
		  "datasets": [
		    {
		      "hash": "<sha3_encoded string>",
		      "userKey": "<pem_encoded public key string>"
		    }
		  ],
		  "algorithm": {
		    "hash": "<sha3_encoded string>",
		    "userKey": "<pem_encoded public key string>"
		  },
		  "result_consumers": [
		    {
		      "userKey": "<pem_encoded public key string>"
		    }
		  ],
		  "agent_config": {
		    "port": "7002",
		    "cert_file": "<pem encoded cert string>",
		    "key_file": "<pem encoded private key string>",
		    "server_ca_file": "<pem encoded cert string>",
		    "client_ca_file": "<pem encoded cert string>",
		    "attested_tls": true
		  }
		}`

		dir, err := os.Getwd()
		if err != nil {
			t.Fatalf("Error getting current working directory: %v", err)
		}

		manifestFile, err := os.CreateTemp(dir, "manifest.json")
		if err != nil {
			t.Fatalf("Error creating temp file: %v", err)
		}
		defer os.Remove(manifestFile.Name())

		err = os.WriteFile(manifestFile.Name(), []byte(fileContent), 0o644)
		if err != nil {
			t.Fatalf("Error writing temp file: %v", err)
		}

		cmd := cli.NewExtendWithManifestCmd()
		cmd.SetArgs([]string{"../scripts/attestation_policy/attestation_policy.json", manifestFile.Name()})

		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		assert.NoError(t, err)
	})
}
