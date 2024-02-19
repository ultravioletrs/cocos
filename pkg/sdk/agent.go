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

func (sdk *agentSDK) Algo(ctx context.Context, algorithm agent.Algorithm) error {
	request := &agent.AlgoRequest{
		Algorithm: algorithm.Algorithm,
		Provider:  algorithm.Provider,
		Id:        algorithm.ID,
	}

	if _, err := sdk.client.Algo(ctx, request); err != nil {
		sdk.logger.Error("Failed to call Algo RPC")
		return err
	}

	return nil
}

func (sdk *agentSDK) Data(ctx context.Context, dataset agent.Dataset) error {
	request := &agent.DataRequest{
		Dataset:  dataset.Dataset,
		Provider: dataset.Provider,
		Id:       dataset.ID,
	}

	if _, err := sdk.client.Data(ctx, request); err != nil {
		sdk.logger.Error("Failed to call Data RPC")
		return err
	}

	return nil
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

func (sdk *agentSDK) Attestation(ctx context.Context, reportData []byte) ([]byte, error) {
	request := &agent.AttestationRequest{
		ReportData: reportData,
	}

	response, err := sdk.client.Attestation(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Attestation RPC")
		return nil, err
	}

	return response.File, nil
}
