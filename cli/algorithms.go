// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/pem"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"google.golang.org/grpc/metadata"
)

var (
	pythonRuntime    string
	algoType         string
	requirementsFile string
	algoArgs         []string
)

func (cli *CLI) NewAlgorithmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "algo",
		Short:   "Upload an algorithm binary",
		Example: "algo <algo_file> <private_key_file_path>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			algorithmFile := args[0]

			cmd.Println("Uploading algorithm file:", algorithmFile)

			algorithm, err := os.ReadFile(algorithmFile)
			if err != nil {
				printError(cmd, "Error reading algorithm file: %v ❌ ", err)
				return
			}

			var req []byte
			if requirementsFile != "" {
				req, err = os.ReadFile(requirementsFile)
				if err != nil {
					printError(cmd, "Error reading requirments file: %v ❌ ", err)
					return
				}
			}

			algoReq := agent.Algorithm{
				Algorithm:    algorithm,
				Requirements: req,
			}

			privKeyFile, err := os.ReadFile(args[1])
			if err != nil {
				printError(cmd, "Error reading private key file: %v ❌ ", err)
				return
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey, err := decodeKey(pemBlock)
			if err != nil {
				printError(cmd, "Error decoding private key: %v ❌ ", err)
				return
			}

			ctx := metadata.NewOutgoingContext(cmd.Context(), metadata.New(make(map[string]string)))

			if err := cli.agentSDK.Algo(addAlgoMetadata(ctx), algoReq, privKey); err != nil {
				printError(cmd, "Failed to upload algorithm due to error: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprint("Successfully uploaded algorithm! ✔ "))
		},
	}

	cmd.Flags().StringVarP(&algoType, "algorithm", "a", string(algorithm.AlgoTypeBin), "Algorithm type to run")
	cmd.Flags().StringVar(&pythonRuntime, "python-runtime", python.PyRuntime, "Python runtime to use")
	cmd.Flags().StringVarP(&requirementsFile, "requirements", "r", "", "Python requirements file")
	cmd.Flags().StringArrayVar(&algoArgs, "args", []string{}, "Arguments to pass to the algorithm")

	return cmd
}

func addAlgoMetadata(ctx context.Context) context.Context {
	ctx = algorithm.AlgorithmTypeToContext(ctx, algoType)
	ctx = algorithm.AlgorithmArgsToContext(ctx, algoArgs)
	ctx = python.PythonRunTimeToContext(ctx, pythonRuntime)
	return ctx
}
