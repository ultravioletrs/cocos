// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package sdk

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/pkg/progressbar"
	"google.golang.org/grpc/metadata"
)

type SDK interface {
	Algo(ctx context.Context, algorithm agent.Algorithm, privKey any) error
	Data(ctx context.Context, dataset agent.Dataset, privKey any) error
	Result(ctx context.Context, privKey any) ([]byte, error)
	Attestation(ctx context.Context, reportData [size64]byte) ([]byte, error)
}

const (
	size64                     = 64
	algoProgressBarDescription = "Uploading algorithm"
	dataProgressBarDescription = "Uploading data"
)

type agentSDK struct {
	client agent.AgentServiceClient
	logger *slog.Logger
}

func NewAgentSDK(log *slog.Logger, agentClient agent.AgentServiceClient) SDK {
	return &agentSDK{
		client: agentClient,
		logger: log,
	}
}

func (sdk *agentSDK) Algo(ctx context.Context, algorithm agent.Algorithm, privKey any) error {
	md, err := generateMetadata(string(auth.AlgorithmProviderRole), privKey)
	if err != nil {
		sdk.logger.Error("Failed to generate metadata")
		return err
	}

	ctx = metadata.NewOutgoingContext(ctx, md)
	stream, err := sdk.client.Algo(ctx)
	if err != nil {
		sdk.logger.Error("Failed to call Algo RPC")
		return err
	}
	algoBuffer := bytes.NewBuffer(algorithm.Algorithm)

	progressbar := progressbar.New()
	progressbar.SendAlgorithm(algoProgressBarDescription, algoBuffer, &stream)

	return nil
}

func (sdk *agentSDK) Data(ctx context.Context, dataset agent.Dataset, privKey any) error {
	md, err := generateMetadata(string(auth.DataProviderRole), privKey)
	if err != nil {
		sdk.logger.Error("Failed to generate metadata")
		return err
	}

	ctx = metadata.NewOutgoingContext(ctx, md)
	stream, err := sdk.client.Data(ctx)
	if err != nil {
		sdk.logger.Error("Failed to call Data RPC")
		return err
	}
	dataBuffer := bytes.NewBuffer(dataset.Dataset)

	progressbar := progressbar.New()
	progressbar.SendData(dataProgressBarDescription, dataBuffer, &stream)

	return nil
}

func (sdk *agentSDK) Result(ctx context.Context, privKey any) ([]byte, error) {
	request := &agent.ResultRequest{}

	md, err := generateMetadata(string(auth.ConsumerRole), privKey)
	if err != nil {
		sdk.logger.Error("Failed to generate metadata")
		return nil, err
	}

	ctx = metadata.NewOutgoingContext(ctx, md)
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

func signData(userID string, privKey crypto.Signer) ([]byte, error) {
	var signature []byte
	var err error

	switch k := privKey.(type) {
	case ed25519.PrivateKey:
		signature, err = k.Sign(rand.Reader, []byte(userID), crypto.Hash(0))
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		hash := sha256.Sum256([]byte(userID))
		signature, err = privKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	default:
		return nil, errors.New("unsupported key type")
	}

	if err != nil {
		return nil, err
	}

	return signature, nil
}

func generateMetadata(userID string, privateKey crypto.PrivateKey) (metadata.MD, error) {
	signature, err := signData(userID, privateKey.(crypto.Signer))
	if err != nil {
		return nil, err
	}

	kv := make(map[string]string)
	kv[auth.UserMetadataKey] = userID
	kv[auth.SignatureMetadataKey] = base64.StdEncoding.EncodeToString(signature)
	return metadata.New(kv), nil
}
