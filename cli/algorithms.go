// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/pem"
	"log"
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

			log.Println("Uploading algorithm file:", algorithmFile)

			algorithm, err := os.ReadFile(algorithmFile)
			if err != nil {
				msg := color.New(color.FgRed).Sprintf("Error reading algorithm file: %v ❌ ", err)
				log.Println(msg)
				return
			}

			var req []byte
			if requirementsFile != "" {
				req, err = os.ReadFile(requirementsFile)
				if err != nil {
					msg := color.New(color.FgRed).Sprintf("Error reading requirments file: %v ❌ ", err)
					log.Println(msg)
					return
				}
			}

			algoReq := agent.Algorithm{
				Algorithm:    algorithm,
				Requirements: req,
			}

			privKeyFile, err := os.ReadFile(args[1])
			if err != nil {
				msg := color.New(color.FgRed).Sprintf("Error reading private key file: %v ❌ ", err.Error())
				log.Println(msg)
				return
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey := decodeKey(pemBlock)

			ctx := metadata.NewOutgoingContext(cmd.Context(), metadata.New(make(map[string]string)))

			if err := cli.agentSDK.Algo(addAlgoMetadata(ctx), algoReq, privKey); err != nil {
				msg := color.New(color.FgRed).Sprintf("Failed to upload algorithm due to error: %v ❌ ", err.Error())
				log.Println(msg)
				return
			}

			log.Println(color.New(color.FgGreen).Sprint("Successfully uploaded algorithm! ✔ "))
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
