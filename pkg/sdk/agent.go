// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package sdk

import (
	"bytes"
	"context"
	"io"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent"
)

var _ agent.Service = (*agentSDK)(nil)

const (
	size64     = 64
	bufferSize = 1024 * 1024
)

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
	stream, err := sdk.client.Algo(ctx)
	if err != nil {
		sdk.logger.Error("Failed to call Algo RPC")
		return err
	}
	algoBuffer := bytes.NewBuffer(algorithm.Algorithm)

	buf := make([]byte, bufferSize)
	for {
		n, err := algoBuffer.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		err = stream.Send(&agent.AlgoRequest{Id: algorithm.ID, Provider: algorithm.Provider, Algorithm: buf[:n]})
		if err != nil {
			return err
		}
	}

	if _, err := stream.CloseAndRecv(); err != nil {
		return err
	}

	return nil
}

func (sdk *agentSDK) Data(ctx context.Context, dataset agent.Dataset) error {
	stream, err := sdk.client.Data(ctx)
	if err != nil {
		sdk.logger.Error("Failed to call Algo RPC")
		return err
	}
	dataBuffer := bytes.NewBuffer(dataset.Dataset)

	buf := make([]byte, bufferSize)
	for {
		n, err := dataBuffer.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		err = stream.Send(&agent.DataRequest{Id: dataset.ID, Provider: dataset.Provider, Dataset: buf[:n]})
		if err != nil {
			return err
		}
	}

	if _, err := stream.CloseAndRecv(); err != nil {
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

func (sdk *agentSDK) Attestation(ctx context.Context, reportData [size64]byte) ([]byte, error) {
	request := &agent.AttestationRequest{
		ReportData: reportData[:],
	}

	response, err := sdk.client.Attestation(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Attestation RPC")
		return nil, err
	}

	return response.File, nil
}
