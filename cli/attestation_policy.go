// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"github.com/spf13/cobra"
)

func (cli *CLI) NewAttestationPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Change attestation policy",
	}

	cmd.AddCommand(cli.NewCreateCoRIMCmd())

	return cmd
}
