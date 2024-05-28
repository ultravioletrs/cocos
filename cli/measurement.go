// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/spf13/cobra"
)

type AttestationConfiguration struct {
	SNPPolicy   *check.Policy      `json:"snp_policy,omitempty"`
	RootOFTrust *check.RootOfTrust `json:"root_of_trust,omitempty"`
}

func (cli *CLI) NewAddMeasurementCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "measurement",
		Short:   "Add measurement to the platform info file. The value should be in base64. The second parameter is platform_info.json file",
		Example: "measurement <measurement> <platform_info.json>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			measurement, err := base64.StdEncoding.DecodeString(args[0])
			if err != nil {
				log.Fatalf("Error could not decode base64: %v", err)
			}

			attestationConfiguration := AttestationConfiguration{}

			manifest, err := os.OpenFile(args[1], os.O_RDWR, 0755)
			if err != nil {
				log.Fatalf("Error opening the platform information file: %v", err)
			}
			defer manifest.Close()

			decoder := json.NewDecoder(manifest)
			err = decoder.Decode(&attestationConfiguration)
			if err != nil {
				log.Fatalf("Error decoding the platform information file: %v", err)
			}

			attestationConfiguration.SNPPolicy.Measurement = measurement
			if err = manifest.Truncate(0); err != nil {
				log.Fatalf("Error could not truncate platform information JSON file: %v", err)
			}

			fileJson, err := json.MarshalIndent(attestationConfiguration, "", " ")
			if err != nil {
				log.Fatalf("Error marshaling the platform information JSON: %v", err)
			}
			if err = os.WriteFile(manifest.Name(), fileJson, 0755); err != nil {
				log.Fatalf("Error writing into platform information JSON file: %v", err)
			}
		},
	}
}
