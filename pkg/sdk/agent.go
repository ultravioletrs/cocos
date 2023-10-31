// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package sdk

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mainflux/mainflux/logger"
	"github.com/ultravioletrs/cocos-ai/agent"
)

type SDK interface {
	Run(ctx context.Context, computation Computation) (string, error)
	UploadAlgorithm(ctx context.Context, algorithm []byte) (string, error)
	UploadDataset(ctx context.Context, dataset []byte) (string, error)
	Result(ctx context.Context) ([]byte, error)
	Attestation(ctx context.Context) ([]byte, error)
}

type agentSDK struct {
	client agent.AgentServiceClient
	logger logger.Logger
}

type Computation struct {
	ID                 string    `json:"id,omitempty" db:"id"`
	Name               string    `json:"name,omitempty" db:"name"`
	Description        string    `json:"description,omitempty" db:"description"`
	Status             string    `json:"status,omitempty" db:"status"`
	Owner              string    `json:"owner,omitempty" db:"owner"`
	StartTime          time.Time `json:"start_time,omitempty" db:"start_time"`
	EndTime            time.Time `json:"end_time,omitempty" db:"end_time"`
	Datasets           []string  `json:"datasets,omitempty" db:"datasets"`
	Algorithms         []string  `json:"algorithms,omitempty" db:"algorithms"`
	DatasetProviders   []string  `json:"dataset_providers,omitempty" db:"dataset_providers"`
	AlgorithmProviders []string  `json:"algorithm_providers,omitempty" db:"algorithm_providers"`
	ResultConsumers    []string  `json:"result_consumers,omitempty" db:"result_consumers"`
	Ttl                int       `json:"ttl,omitempty" db:"ttl"`
	Metadata           Metadata  `json:"metadata,omitempty" db:"metadata"`
}

type Metadata map[string]interface{}

func NewAgentSDK(log logger.Logger, agentClient agent.AgentServiceClient) *agentSDK {
	return &agentSDK{
		client: agentClient,
		logger: log,
	}
}

func (sdk *agentSDK) Run(ctx context.Context, computation Computation) (string, error) {
	computationBytes, err := json.Marshal(computation)
	if err != nil {
		sdk.logger.Error("Failed to marshal computation")
		return "", err
	}

	request := &agent.RunRequest{
		Computation: computationBytes,
	}
	response, err := sdk.client.Run(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Run RPC")
		return "", err
	}

	return response.Computation, nil
}

func (sdk *agentSDK) UploadAlgorithm(ctx context.Context, algorithm []byte) (string, error) {
	request := &agent.AlgoRequest{
		Algorithm: algorithm,
	}

	response, err := sdk.client.Algo(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Algo RPC")
		return "", err
	}

	return response.AlgorithmID, nil
}

func (sdk *agentSDK) UploadDataset(ctx context.Context, dataset []byte) (string, error) {
	request := &agent.DataRequest{
		Dataset: dataset,
	}

	response, err := sdk.client.Data(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Data RPC")
		return "", err
	}

	return response.DatasetID, nil
}

func (sdk *agentSDK) Result(ctx context.Context) ([]byte, error) {
	request := &agent.ResultRequest{}

	response, err := sdk.client.Result(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Result RPC")
		return nil, err
	}

	return response.File, nil
}

func (sdk *agentSDK) Attestation(ctx context.Context) ([]byte, error) {
	request := &agent.AttestationRequest{}

	response, err := sdk.client.Attestation(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Attestation RPC")
		return nil, err
	}

	return response.File, nil
}
