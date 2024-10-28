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
	"strconv"

	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/pkg/progressbar"
	"google.golang.org/grpc/metadata"
)

//go:generate mockery --name SDK --output=mocks --filename sdk.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type SDK interface {
	Algo(ctx context.Context, algorithm agent.Algorithm, privKey any) error
	Data(ctx context.Context, dataset agent.Dataset, privKey any) error
	Result(ctx context.Context, privKey any) ([]byte, error)
	Attestation(ctx context.Context, reportData [size64]byte) ([]byte, error)
}

const (
	size64                         = 64
	algoProgressBarDescription     = "Uploading algorithm"
	dataProgressBarDescription     = "Uploading data"
	resultProgressDescription      = "Downloading result"
	attestationProgressDescription = "Downloading attestation"
)

type agentSDK struct {
	client agent.AgentServiceClient
}

func NewAgentSDK(agentClient agent.AgentServiceClient) SDK {
	return &agentSDK{
		client: agentClient,
	}
}

func (sdk *agentSDK) Algo(ctx context.Context, algorithm agent.Algorithm, privKey any) error {
	md, err := generateMetadata(string(auth.AlgorithmProviderRole), privKey)
	if err != nil {
		return err
	}

	for k, v := range md {
		ctx = metadata.AppendToOutgoingContext(ctx, k, v[0])
	}

	stream, err := sdk.client.Algo(ctx)
	if err != nil {
		return err
	}
	algoBuffer := bytes.NewBuffer(algorithm.Algorithm)
	reqBuffer := bytes.NewBuffer(algorithm.Requirements)

	pb := progressbar.New(false)
	return pb.SendAlgorithm(algoProgressBarDescription, algoBuffer, reqBuffer, &stream)
}

func (sdk *agentSDK) Data(ctx context.Context, dataset agent.Dataset, privKey any) error {
	md, err := generateMetadata(string(auth.DataProviderRole), privKey)
	if err != nil {
		return err
	}

	for k, v := range md {
		ctx = metadata.AppendToOutgoingContext(ctx, k, v[0])
	}

	stream, err := sdk.client.Data(ctx)
	if err != nil {
		return err
	}
	dataBuffer := bytes.NewBuffer(dataset.Dataset)

	pb := progressbar.New(false)
	return pb.SendData(dataProgressBarDescription, dataset.Filename, dataBuffer, &stream)
}

func (sdk *agentSDK) Result(ctx context.Context, privKey any) ([]byte, error) {
	request := &agent.ResultRequest{}

	md, err := generateMetadata(string(auth.ConsumerRole), privKey)
	if err != nil {
		return nil, err
	}

	ctx = metadata.NewOutgoingContext(ctx, md)
	stream, err := sdk.client.Result(ctx, request)
	if err != nil {
		return nil, err
	}

	incomingmd, err := stream.Header()
	if err != nil {
		return nil, err
	}

	fileSizeStr := incomingmd.Get(grpc.FileSizeKey)

	fileSize, err := strconv.Atoi(fileSizeStr[0])
	if err != nil {
		return nil, err
	}

	pb := progressbar.New(true)

	return pb.ReceiveResult(resultProgressDescription, fileSize, stream)
}

func (sdk *agentSDK) Attestation(ctx context.Context, reportData [size64]byte) ([]byte, error) {
	request := &agent.AttestationRequest{
		ReportData: reportData[:],
	}

	stream, err := sdk.client.Attestation(ctx, request)
	if err != nil {
		return nil, err
	}

	incomingmd, err := stream.Header()
	if err != nil {
		return nil, err
	}

	fileSizeStr := incomingmd.Get(grpc.FileSizeKey)

	fileSize, err := strconv.Atoi(fileSizeStr[0])
	if err != nil {
		return nil, err
	}

	pb := progressbar.New(true)

	return pb.ReceiveAttestation(attestationProgressDescription, fileSize, stream)
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
