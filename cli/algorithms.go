// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/pem"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/docker"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"google.golang.org/grpc/metadata"
)

var (
	pythonRuntime    string
	algoType         string
	requirementsFile string
	dockerCommand    string
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
				log.Fatalf("Error reading algorithm file: %v", err)
			}

			var req []byte
			if requirementsFile != "" {
				req, err = os.ReadFile(requirementsFile)
				if err != nil {
					log.Fatalf("Error reading requirments file: %v", err)
				}
			}

			algoReq := agent.Algorithm{
				Algorithm:    algorithm,
				Requirements: req,
			}

			privKeyFile, err := os.ReadFile(args[1])
			if err != nil {
				log.Fatalf("Error reading private key file: %v", err)
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey := decodeKey(pemBlock)

			ctx := metadata.NewOutgoingContext(cmd.Context(), metadata.New(make(map[string]string)))

			if err := cli.agentSDK.Algo(addAlgoMetadata(ctx), algoReq, privKey); err != nil {
				log.Fatalf("Error uploading algorithm with error: %v", err)
			}

			log.Println("Successfully uploaded algorithm")
		},
	}

	cmd.Flags().StringVarP(&algoType, "algorithm", "a", string(algorithm.AlgoTypeBin), "Algorithm type to run")
	cmd.Flags().StringVar(&pythonRuntime, "python-runtime", python.PyRuntime, "Python runtime to use")
	cmd.Flags().StringVarP(&requirementsFile, "requirements", "r", "", "Python requirements file")
	cmd.Flags().StringVarP(&dockerCommand, "dockerc", "d", docker.DockerRunCommand, "The docker start command")

	return cmd
}

func addAlgoMetadata(ctx context.Context) context.Context {
	ctx = algorithm.AlgorithmTypeToContext(ctx, algoType)
	ctx = python.PythonRunTimeToContext(ctx, pythonRuntime)
	ctx = docker.DockerRunCommandToContext(ctx, dockerCommand)
	return ctx
}
