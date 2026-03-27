// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/manager"
)

const (
	serverURL = "server-url"
	serverCA  = "server-ca"
	clientKey = "client-key"
	clientCrt = "client-crt"
	caUrl     = "ca-url"
	logLevel  = "log-level"
	ttlFlag   = "ttl"
)


func (c *CLI) NewCreateVMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create-vm",
		Short:   "Create a new virtual machine",
		Example: `create-vm`,
		Args:    cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			if c.connectErr != nil {
				c.printError(cmd, "Failed to connect to manager: %v ❌ ", c.connectErr)
				return
			}
			if c.managerClient == nil {
				if err := c.InitializeManagerClient(cmd); err != nil {
					c.printError(cmd, "Failed to connect to manager: %v ❌ ", err)
					return
				}
			}
			defer c.Close()

			createReq, err := c.loadCerts()
			if err != nil {
				c.printError(cmd, "Error loading certs: %v ❌ ", err)
				return
			}

			createReq.AgentCvmServerUrl = c.AgentCVMServerUrl
			createReq.AgentLogLevel = c.AgentLogLevel
			createReq.AgentCvmCaUrl = c.AgentCVMCaUrl
			createReq.AwsAccessKeyId = c.AwsAccessKeyId
			createReq.AwsSecretAccessKey = c.AwsSecretAccessKey
			createReq.AwsEndpointUrl = c.AwsEndpointUrl
			createReq.AwsRegion = c.AwsRegion
			createReq.AaKbsParams = c.AaKbsParams

			if c.Ttl > 0 {
				createReq.Ttl = c.Ttl.String()
			}

			cmd.Println("🔗 Creating a new virtual machine")

			res, err := c.managerClient.CreateVm(cmd.Context(), createReq)
			if err != nil {
				c.printError(cmd, "Error creating virtual machine: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("✅ Virtual machine created successfully with id %s and port %s", res.CvmId, res.ForwardedPort))
		},
	}

	cmd.Flags().StringVar(&c.AgentCVMServerUrl, serverURL, "", "CVM server URL")
	cmd.Flags().StringVar(&c.AgentCVMServerCA, serverCA, "", "CVM server CA")
	cmd.Flags().StringVar(&c.AgentCVMClientKey, clientKey, "", "CVM client key")
	cmd.Flags().StringVar(&c.AgentCVMClientCrt, clientCrt, "", "CVM client crt")
	cmd.Flags().StringVar(&c.AgentCVMCaUrl, caUrl, "", "CVM CA service URL")
	cmd.Flags().StringVar(&c.AgentLogLevel, logLevel, "", "Agent Log level")
	cmd.Flags().DurationVar(&c.Ttl, ttlFlag, 0, "TTL for the VM")
	cmd.Flags().StringVar(&c.AwsAccessKeyId, "aws-access-key-id", "", "AWS Access Key ID for S3/MinIO")
	cmd.Flags().StringVar(&c.AwsSecretAccessKey, "aws-secret-access-key", "", "AWS Secret Access Key for S3/MinIO")
	cmd.Flags().StringVar(&c.AwsEndpointUrl, "aws-endpoint-url", "", "AWS Endpoint URL (for MinIO or custom S3)")
	cmd.Flags().StringVar(&c.AwsRegion, "aws-region", "", "AWS Region")
	cmd.Flags().StringVar(&c.AaKbsParams, "aa-kbs-params", "", "Attestation Agent KBS Parameters (e.g. protocol=http,type=kbs,url=http://... or just type=sample)")
	if err := cmd.MarkFlagRequired(serverURL); err != nil {
		c.printError(cmd, "Error marking flag as required: %v ❌ ", err)
		return cmd
	}

	return cmd
}

func (c *CLI) NewRemoveVMCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove-vm",
		Short:   "Remove a virtual machine",
		Example: `remove-vm <cvm_id>`,
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if c.connectErr != nil {
				c.printError(cmd, "Failed to connect to manager: %v ❌ ", c.connectErr)
				return
			}
			if c.managerClient == nil {
				if err := c.InitializeManagerClient(cmd); err != nil {
					c.printError(cmd, "Failed to connect to manager: %v ❌ ", err)
					return
				}
			}
			defer c.Close()

			cmd.Println("🔗 Removing virtual machine")

			_, err := c.managerClient.RemoveVm(cmd.Context(), &manager.RemoveReq{CvmId: args[0]})
			if err != nil {
				c.printError(cmd, "Error removing virtual machine: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("✅ Virtual machine removed successfully"))
		},
	}
}

func fileReader(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}

	return os.ReadFile(path)
}

func (c *CLI) loadCerts() (*manager.CreateReq, error) {
	clientKey, err := fileReader(c.AgentCVMClientKey)
	if err != nil {
		return nil, err
	}

	clientCrt, err := fileReader(c.AgentCVMClientCrt)
	if err != nil {
		return nil, err
	}

	serverCA, err := fileReader(c.AgentCVMServerCA)
	if err != nil {
		return nil, err
	}

	return &manager.CreateReq{
		AgentCvmServerCaCert: serverCA,
		AgentCvmClientKey:    clientKey,
		AgentCvmClientCert:   clientCrt,
	}, nil
}
