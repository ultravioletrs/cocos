// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
	"golang.org/x/crypto/sha3"
)

var (
	algoPath = "../test/manual/algo/lin_reg.py"
	dataPath = "../test/manual/data/iris.csv"
)

func TestAlgo(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, json.RawMessage{}).Return(nil)
	defer evCall.Unset()

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	testCases := []struct {
		name string
		err  error
		algo agent.Algorithm
	}{
		{
			name: "Test Algo successfully",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			err: nil,
		},
		{
			name: "Test State not ready",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			err: agent.ErrStateNotReady,
		},
		{
			name: "Test algo hash mismatch",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      sha3.Sum256([]byte{}),
			},
			err: agent.ErrHashMismatch,
		},
		{
			name: "Test missing algorithm",
			algo: agent.Algorithm{
				Hash: algoHash,
			},
			err: agent.ErrAllManifestItemsReceived,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t))

			err = svc.Algo(ctx, tc.algo)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestData(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, json.RawMessage{}).Return(nil)
	defer evCall.Unset()

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	algorithm := agent.Algorithm{
		Hash:      algoHash,
		Algorithm: algo,
	}

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(data)

	cases := []struct {
		name string
		data agent.Dataset
		err  error
	}{
		{
			name: "Test data successfully",
			data: agent.Dataset{
				Hash:    dataHash,
				Dataset: data,
			},
		},
		{
			name: "Test State not ready",
			data: agent.Dataset{
				Dataset: data,
				Hash:    algoHash,
			},
			err: agent.ErrStateNotReady,
		},
		{
			name: "Test data hash mismatch",
			data: agent.Dataset{
				Dataset: data,
				Hash:    sha3.Sum256([]byte{}),
			},
			err: agent.ErrHashMismatch,
		},
		{
			name: "Test missing data",
			data: agent.Dataset{
				Hash: algoHash,
			},
			err: agent.ErrAllManifestItemsReceived,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), "testName", "test"))
			defer cancel()
			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t))

			if tc.err != agent.ErrStateNotReady {
				_ = svc.Algo(ctx, algorithm)
			}
			_ = svc.Data(ctx, tc.data)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestResult(t *testing.T) {
	events := new(mocks.Service)
	ctx := context.Background()

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	algorithm := agent.Algorithm{
		Hash:      algoHash,
		Algorithm: algo,
	}

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(data)

	dataset := agent.Dataset{
		Hash:    dataHash,
		Dataset: data,
	}

	response := &agent.ResultResponse{
		File: []byte{
			0x01, 0x02, 0x03, 0x04,
			0x05, 0x06, 0x07, 0x08,
		},
	}

	cases := []struct {
		name     string
		userKey  any
		response *agent.ResultResponse
		svcRes   []byte
		err      error
	}{
		{
			name:     "Test result successfully",
			response: response,
			svcRes:   response.File,
			err:      nil,
		},
		{
			name:     "Test State not ready",
			response: response,
			svcRes:   response.File,
			err:      nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evCall := events.On("SendEvent", mock.Anything, mock.Anything, json.RawMessage{}).Return(nil)
			defer evCall.Unset()

			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t))
			if tc.err != agent.ErrStateNotReady {
				_ = svc.Algo(ctx, algorithm)
				_ = svc.Data(ctx, dataset)
			}
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func testComputation(t *testing.T) agent.Computation {
	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(algo)

	return agent.Computation{
		ID:              "1",
		Name:            "sample computation",
		Description:     "sample description",
		Datasets:        []agent.Dataset{{Hash: dataHash, UserKey: []byte{}, Dataset: data}},
		Algorithm:       agent.Algorithm{Hash: algoHash, UserKey: []byte{}, Algorithm: algo},
		ResultConsumers: []agent.ResultConsumer{{UserKey: []byte{}}},
		AgentConfig: agent.AgentConfig{
			Port:        "7002",
			LogLevel:    "debug",
			AttestedTls: false,
		},
	}
}
