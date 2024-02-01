// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/json"
	"log"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager"
)

func (cli *CLI) NewRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "run",
		Short:   "Upload a computation manifest json",
		Example: "run '<computation>'",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			computationStr := args[0]

			var cmp agent.Computation
			if err := json.Unmarshal([]byte(computationStr), &cmp); err != nil {
				log.Fatalf("Error unmarshling computation json: %v", err)
			}

			req := manager.Computation{
				Id:              cmp.ID,
				Description:     cmp.Description,
				Name:            cmp.Name,
				ResultConsumers: cmp.ResultConsumers,
				AgentConfig: &manager.AgentConfig{
					Port:     cmp.AgentConfig.Port,
					Host:     cmp.AgentConfig.Host,
					CertFile: cmp.AgentConfig.CertFile,
					KeyFile:  cmp.AgentConfig.KeyFile,
					LogLevel: cmp.AgentConfig.LogLevel,
				},
			}

			for _, data := range cmp.Datasets {
				req.Datasets = append(req.Datasets, &manager.Dataset{Id: data.ID, Provider: data.Provider})
			}

			for _, algo := range cmp.Algorithms {
				req.Algorithms = append(req.Algorithms, &manager.Algorithm{Id: algo.ID, Provider: algo.Provider})
			}

			response, err := cli.managerSDK.Run(cmd.Context(), &req)
			if err != nil {
				log.Fatalf("Error running computation: %v", err)
			}

			log.Printf("Successfully run computation, agent address: %v", response)
		},
	}
}
