// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/corimgen"
	"github.com/ultravioletrs/cocos/pkg/attestation/gcp"
	"github.com/ultravioletrs/cocos/pkg/attestation/generator"
)

func (cli *CLI) NewCreateCoRIMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-corim",
		Short: "Create CoRIM attestation policy",
		Long:  `Create CoRIM attestation policy for supported platforms (Azure, GCP, SNP, TDX)`,
	}

	cmd.AddCommand(cli.NewCreateCoRIMAzureCmd())
	cmd.AddCommand(cli.NewCreateCoRIMGCPCmd())
	cmd.AddCommand(cli.NewCreateCoRIMSNPCmd())
	cmd.AddCommand(cli.NewCreateCoRIMTDXCmd())

	return cmd
}

func (cli *CLI) NewCreateCoRIMAzureCmd() *cobra.Command {
	var tokenPath string
	var product string
	var output string
	var signingKeyPath string

	cmd := &cobra.Command{
		Use:   "azure",
		Short: "Create CoRIM for Azure SEV-SNP",
		RunE: func(cmd *cobra.Command, args []string) error {
			tokenBytes, err := os.ReadFile(tokenPath)
			if err != nil {
				return fmt.Errorf("failed to read token file: %w", err)
			}

			azureData, err := azure.ExtractAzureMeasurement(string(tokenBytes))
			if err != nil {
				return fmt.Errorf("failed to extract Azure measurements: %w", err)
			}

			opts := generator.Options{
				Platform:    "snp",
				Measurement: azureData.Measurement,
				HostData:    azureData.HostData,
				Policy:      azureData.Policy,
				SVN:         azureData.SVN,
				Product:     product,
			}

			if signingKeyPath != "" {
				key, err := corimgen.LoadSigningKey(signingKeyPath)
				if err != nil {
					return fmt.Errorf("failed to load signing key: %w", err)
				}
				opts.SigningKey = key
			}

			cborBytes, err := generator.GenerateCoRIM(opts)
			if err != nil {
				return fmt.Errorf("failed to generate CoRIM: %w", err)
			}

			if output != "" {
				if err := os.WriteFile(output, cborBytes, 0o644); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "CoRIM written to %s\n", output)
			} else {
				if _, err := os.Stdout.Write(cborBytes); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&tokenPath, "token", "", "Path to file containing Azure Attestation Token (JWT)")
	cmd.Flags().StringVar(&product, "product", "Milan", "Processor product name (Milan, Genoa)")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "Path to private key for signing (PEM format)")
	_ = cmd.MarkFlagRequired("token")

	return cmd
}

func (cli *CLI) NewCreateCoRIMGCPCmd() *cobra.Command {
	var measurement string
	var vcpuNum uint32
	var output string
	var signingKeyPath string

	cmd := &cobra.Command{
		Use:   "gcp",
		Short: "Create CoRIM for GCP SEV-SNP",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			endorsement, err := gcp.GetLaunchEndorsement(ctx, measurement)
			if err != nil {
				return fmt.Errorf("failed to get launch endorsement: %w", err)
			}

			gcpData, err := gcp.ExtractGCPMeasurement(endorsement, vcpuNum)
			if err != nil {
				return fmt.Errorf("failed to extract GCP measurements: %w", err)
			}

			opts := generator.Options{
				Platform:    "snp",
				Measurement: gcpData.Measurement,
				Policy:      gcpData.Policy,
			}

			if signingKeyPath != "" {
				key, err := corimgen.LoadSigningKey(signingKeyPath)
				if err != nil {
					return fmt.Errorf("failed to load signing key: %w", err)
				}
				opts.SigningKey = key
			}

			cborBytes, err := generator.GenerateCoRIM(opts)
			if err != nil {
				return fmt.Errorf("failed to generate CoRIM: %w", err)
			}

			if output != "" {
				if err := os.WriteFile(output, cborBytes, 0o644); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "CoRIM written to %s\n", output)
			} else {
				if _, err := os.Stdout.Write(cborBytes); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&measurement, "measurement", "", "384-bit measurement hex string")
	cmd.Flags().Uint32Var(&vcpuNum, "vcpu", 0, "vCPU number")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "Path to private key for signing (PEM format)")
	_ = cmd.MarkFlagRequired("measurement")

	return cmd
}

func (cli *CLI) NewCreateCoRIMSNPCmd() *cobra.Command {
	var (
		measurement    string
		policy         uint64
		svn            uint64
		product        string
		hostData       string
		launchTCB      uint64
		output         string
		signingKeyPath string
	)

	cmd := &cobra.Command{
		Use:   "snp",
		Short: "Create CoRIM for SEV-SNP",
		Long:  `Generate CoRIM attestation policy for AMD SEV-SNP platform`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := generator.Options{
				Platform:    "snp",
				Measurement: measurement,
				Policy:      policy,
				SVN:         svn,
				Product:     product,
				HostData:    hostData,
				LaunchTCB:   launchTCB,
			}

			if signingKeyPath != "" {
				key, err := corimgen.LoadSigningKey(signingKeyPath)
				if err != nil {
					return fmt.Errorf("failed to load signing key: %w", err)
				}
				opts.SigningKey = key
			}

			cborBytes, err := generator.GenerateCoRIM(opts)
			if err != nil {
				return fmt.Errorf("failed to generate CoRIM: %w", err)
			}

			if output != "" {
				if err := os.WriteFile(output, cborBytes, 0o644); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "CoRIM written to %s\n", output)
			} else {
				if _, err := os.Stdout.Write(cborBytes); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&measurement, "measurement", "", "Measurement/Launch Digest (hex string, defaults to zero if not provided)")
	cmd.Flags().Uint64Var(&policy, "policy", 0, "SNP policy flags")
	cmd.Flags().Uint64Var(&svn, "svn", 0, "Security Version Number (TCB)")
	cmd.Flags().StringVar(&product, "product", "Milan", "Processor product name (Milan, Genoa, etc.)")
	cmd.Flags().StringVar(&hostData, "host-data", "", "Host data (hex string)")
	cmd.Flags().Uint64Var(&launchTCB, "launch-tcb", 0, "Minimum launch TCB")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "Path to private key for signing (PEM format)")

	return cmd
}

func (cli *CLI) NewCreateCoRIMTDXCmd() *cobra.Command {
	var (
		measurement    string
		svn            uint64
		rtmrs          string
		mrSeam         string
		output         string
		signingKeyPath string
	)

	cmd := &cobra.Command{
		Use:   "tdx",
		Short: "Create CoRIM for Intel TDX",
		Long:  `Generate CoRIM attestation policy for Intel TDX platform`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := generator.Options{
				Platform:    "tdx",
				Measurement: measurement,
				SVN:         svn,
				RTMRs:       rtmrs,
				MrSeam:      mrSeam,
			}

			if signingKeyPath != "" {
				key, err := corimgen.LoadSigningKey(signingKeyPath)
				if err != nil {
					return fmt.Errorf("failed to load signing key: %w", err)
				}
				opts.SigningKey = key
			}

			cborBytes, err := generator.GenerateCoRIM(opts)
			if err != nil {
				return fmt.Errorf("failed to generate CoRIM: %w", err)
			}

			if output != "" {
				if err := os.WriteFile(output, cborBytes, 0o644); err != nil {
					return fmt.Errorf("failed to write output file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "CoRIM written to %s\n", output)
			} else {
				if _, err := os.Stdout.Write(cborBytes); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&measurement, "measurement", "", "MRTD measurement (hex string, uses default if not provided)")
	cmd.Flags().Uint64Var(&svn, "svn", 0, "Security Version Number")
	cmd.Flags().StringVar(&rtmrs, "rtmrs", "", "Comma-separated RTMRs (hex)")
	cmd.Flags().StringVar(&mrSeam, "mr-seam", "", "MRSEAM (hex)")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&signingKeyPath, "signing-key", "", "Path to private key for signing (PEM format)")

	return cmd
}
