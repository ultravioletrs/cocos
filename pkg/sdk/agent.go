// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package sdk

import (
	"context"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent"
)

var _ agent.Service = (*agentSDK)(nil)

type agentSDK struct {
	client agent.AgentServiceClient
	logger *slog.Logger
}

func NewAgentSDK(log *slog.Logger, agentClient agent.AgentServiceClient) *agentSDK {
	return &agentSDK{
		client: agentClient,
		logger: log,
	}
}

func (sdk *agentSDK) Run(ctx context.Context, ac agent.Computation) (string, error) {
	return "", nil
}

func (sdk *agentSDK) Algo(ctx context.Context, algorithm agent.Algorithm) (string, error) {
	request := &agent.AlgoRequest{
		Algorithm: algorithm.Algorithm,
		Provider:  algorithm.Provider,
		Id:        algorithm.ID,
	}

	response, err := sdk.client.Algo(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Algo RPC")
		return "", err
	}

	return response.AlgorithmID, nil
}

func (sdk *agentSDK) Data(ctx context.Context, dataset agent.Dataset) (string, error) {
	request := &agent.DataRequest{
		Dataset:  dataset.Dataset,
		Provider: dataset.Provider,
		Id:       dataset.ID,
	}

	response, err := sdk.client.Data(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Data RPC")
		return "", err
	}

	return response.DatasetID, nil
}

func (sdk *agentSDK) Result(ctx context.Context, consumer string) ([]byte, error) {
	request := &agent.ResultRequest{
		Consumer: consumer,
	}

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
