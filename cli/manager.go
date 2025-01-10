// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/manager"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (c *CLI) NewCreateVMCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "create-vm",
		Short:   "Create a new virtual machine",
		Example: `create-vm`,
		Args:    cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if err := c.InitializeManagerClient(cmd); err == nil {
				defer c.Close()
			}

			if c.connectErr != nil {
				printError(cmd, "Failed to connect to manager: %v ❌ ", c.connectErr)
				return
			}

			cmd.Println("🔗 Creating a new virtual machine")

			res, err := c.managerClient.CreateVm(cmd.Context(), &emptypb.Empty{})
			if err != nil {
				printError(cmd, "Error creating virtual machine: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("✅ Virtual machine created successfully with id %s and port %s", res.SvmId, res.ForwardedPort))
		},
	}
}

func (c *CLI) NewRemoveVMCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove-vm",
		Short:   "Remove a virtual machine",
		Example: `remove-vm <svm_id>`,
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := c.InitializeManagerClient(cmd); err == nil {
				defer c.Close()
			}

			if c.connectErr != nil {
				printError(cmd, "Failed to connect to manager: %v ❌ ", c.connectErr)
				return
			}

			cmd.Println("🔗 Removing virtual machine")

			_, err := c.managerClient.RemoveVm(cmd.Context(), &manager.RemoveReq{SvmId: args[0]})
			if err != nil {
				printError(cmd, "Error removing virtual machine: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("✅ Virtual machine removed successfully"))
		},
	}
}
