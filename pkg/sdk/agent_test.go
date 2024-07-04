// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"testing"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	agentMocks "github.com/ultravioletrs/cocos/agent/mocks"
	"github.com/ultravioletrs/cocos/pkg/sdk"
	"golang.org/x/crypto/sha3"
)

var (
	algoPath = "../../test/manual/algo/lin_reg.py"
	dataPath = "../../test/manual/data/iris.csv"
)

func TestAlgo(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	agmocks := new(agentMocks.AgentServiceClient)
	sdk := sdk.NewAgentSDK(logger, agmocks)

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	algorithmProviderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	algorithmProviderPubKey, err := x509.MarshalPKIXPublicKey(&algorithmProviderKey.PublicKey)
	require.NoError(t, err)

	algorithm := agent.Algorithm{
		Algorithm: algo,
		Hash:      algoHash,
		UserKey:   algorithmProviderPubKey,
	}

	cases := []struct {
		name     string
		err      error
		algo     agent.Algorithm
		userKey  *rsa.PrivateKey
		stream   *agentMocks.AgentServiceClient
		sendErr  error
		closeErr error
	}{
		{
			name:    "Test Algo successfully",
			stream:  agmocks,
			algo:    algorithm,
			userKey: algorithmProviderKey,
			err:     nil,
		},
		{
			name:   "missing pubkey in algo",
			stream: agmocks,
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			userKey: algorithmProviderKey,
			err:     nil,
		},
		{
			name:   "missing hash",
			stream: agmocks,
			algo: agent.Algorithm{
				Algorithm: algo,
				UserKey:   algorithmProviderPubKey,
			},
			userKey: algorithmProviderKey,
			err:     errors.New("failed to hash"),
		},
		{
			name:   "missing algo",
			stream: agmocks,
			algo: agent.Algorithm{
				UserKey: algorithmProviderPubKey,
				Hash:    algoHash,
			},
			userKey: algorithmProviderKey,
		},
		{
			name:    "test algorithm with failed to send",
			stream:  agmocks,
			algo:    algorithm,
			userKey: algorithmProviderKey,
			sendErr: errors.New("failed to send"),
		},
		{
			name:     "test algorithm with failed to close buffer",
			stream:   agmocks,
			algo:     algorithm,
			userKey:  algorithmProviderKey,
			closeErr: errors.New("failed to close buffer"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algoCall := agmocks.On("Algo", mock.Anything).Return(tc.stream, tc.err)
			sendCall := tc.stream.On("Send", mock.Anything).Return(tc.sendErr)
			closeCall := tc.stream.On("CloseAndRecv").Return(nil, tc.closeErr)
			err = sdk.Algo(context.Background(), tc.algo, tc.userKey)
			switch {
			case tc.sendErr != nil:
				assert.Equal(t, tc.sendErr, err, tc.name)
			case tc.closeErr != nil:
				assert.Equal(t, tc.closeErr, err, tc.name)
			default:
				assert.Equal(t, tc.err, err, tc.name)
			}

			sendCall.Unset()
			algoCall.Unset()
			closeCall.Unset()
		})
	}
}

func TestData(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	agmocks := new(agentMocks.AgentService_DataClient)
	agM := new(agentMocks.AgentServiceClient)
	sdk := sdk.NewAgentSDK(logger, agM)

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(data)

	dataProviderKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	dataProviderPubKey, err := x509.MarshalPKIXPublicKey(&dataProviderKey.PublicKey)
	require.NoError(t, err)

	dataset := agent.Dataset{
		Hash:    dataHash,
		Dataset: data,
		UserKey: dataProviderPubKey,
	}

	cases := []struct {
		name     string
		err      error
		data     agent.Dataset
		userKey  *rsa.PrivateKey
		stream   *agentMocks.AgentService_DataClient
		sendErr  error
		closeErr error
	}{
		{
			name:    "Test data successfully",
			stream:  agmocks,
			data:    dataset,
			userKey: dataProviderKey,
			err:     nil,
		},
		{
			name:   "missing pubkey in dataset",
			stream: agmocks,
			data: agent.Dataset{
				Dataset: data,
				Hash:    dataHash,
			},
			userKey: dataProviderKey,
			err:     nil,
		},
		{
			name:   "missing hash",
			stream: agmocks,
			data: agent.Dataset{
				Dataset: data,
				UserKey: dataProviderPubKey,
			},
			userKey: dataProviderKey,
			err:     errors.New("failed to hash"),
		},
		{
			name:   "missing dataset",
			stream: agmocks,
			data: agent.Dataset{
				UserKey: dataProviderPubKey,
				Hash:    dataHash,
			},
			userKey: dataProviderKey,
		},
		{
			name:    "test dataset with failed to send",
			stream:  agmocks,
			data:    dataset,
			userKey: dataProviderKey,
			sendErr: errors.New("failed to send"),
		},
		{
			name:     "test dataset with failed to close buffer",
			stream:   agmocks,
			data:     dataset,
			userKey:  dataProviderKey,
			closeErr: errors.New("failed to close buffer"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algoCall := agM.On("Data", mock.Anything).Return(tc.stream, tc.err)
			sendCall := tc.stream.On("Send", mock.Anything).Return(tc.sendErr)
			closeCall := tc.stream.On("CloseAndRecv").Return(nil, tc.closeErr)
			err = sdk.Data(context.Background(), tc.data, tc.userKey)
			switch {
			case tc.sendErr != nil:
				assert.Equal(t, tc.sendErr, err, tc.name)
			case tc.closeErr != nil:
				assert.Equal(t, tc.closeErr, err, tc.name)
			default:
				assert.Equal(t, tc.err, err, tc.name)
			}

			sendCall.Unset()
			algoCall.Unset()
			closeCall.Unset()
		})
	}
}

func TestResult(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	agmocks := new(agentMocks.AgentServiceClient)
	sdk := sdk.NewAgentSDK(logger, agmocks)

	resultConsumerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	response := &agent.ResultResponse{
		File: []byte{},
	}
	// resultConsumerPubKey, err := x509.MarshalPKIXPublicKey(&resultConsumerKey.PublicKey)
	// require.NoError(t, err)

	cases := []struct {
		name     string
		userKey  *rsa.PrivateKey
		response *agent.ResultResponse
		err      error
	}{
		{
			name:     "Test result successfully",
			userKey:  resultConsumerKey,
			response: response,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resultCall := agmocks.On("Result", mock.Anything, &agent.ResultRequest{}).Return(tc.response, tc.err)

			res, err := sdk.Result(context.Background(), tc.userKey)
			assert.Equal(t, tc.err, err, tc.name)
			assert.Equal(t, tc.response.File, res, tc.name)

			resultCall.Unset()
		})
	}
}

func TestAttestation(t *testing.T) {
	logger, err := mglog.New(os.Stdout, "info")
	require.NoError(t, err)

	agmocks := new(agentMocks.AgentServiceClient)
	sdk := sdk.NewAgentSDK(logger, agmocks)

	resultConsumerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	reportData := make([]byte, 64)

	_, err = rand.Read(reportData)
	require.NoError(t, err)

	cases := []struct {
		name       string
		userKey    *rsa.PrivateKey
		reportData [agent.ReportDataSize]byte
		response   *agent.AttestationResponse
		err        error
	}{
		{
			name:       "Test result successfully",
			userKey:    resultConsumerKey,
			reportData: [agent.ReportDataSize]byte(reportData),
			response: &agent.AttestationResponse{
				File: []byte{},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resultCall := agmocks.On("Attestation", mock.Anything, &agent.AttestationRequest{ReportData: tc.reportData[:]}).Return(tc.response, tc.err)

			res, err := sdk.Attestation(context.Background(), tc.reportData)
			assert.Equal(t, tc.err, err, tc.name)
			assert.Equal(t, tc.response.File, res, tc.name)

			resultCall.Unset()
		})
	}
}
