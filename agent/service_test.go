// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent_test

import (
	"context"
	"os"
	"testing"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/metadata"
)

var (
	algoPath = "../test/manual/algo/lin_reg.py"
	dataPath = "../test/manual/data/iris.csv"
)

const datasetFile = "iris.csv"

func TestAlgo(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	testCases := []struct {
		name     string
		err      error
		algo     agent.Algorithm
		algoType string
	}{
		{
			name: "Test Algo successfully",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "python",
			err:      nil,
		},
		{
			name:     "Test algo hash mismatch",
			algo:     agent.Algorithm{},
			algoType: "python",
			err:      agent.ErrHashMismatch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, tc.algoType, python.PyRuntimeKey, python.PyRuntime),
			)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t))

			time.Sleep(300 * time.Millisecond)

			err = svc.Algo(ctx, tc.algo)
			_ = os.RemoveAll("datasets")

			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestData(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	alg := agent.Algorithm{
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
				Hash:     dataHash,
				Dataset:  data,
				Filename: datasetFile,
			},
		},
		{
			name: "Test State not ready",
			data: agent.Dataset{
				Dataset:  data,
				Hash:     dataHash,
				Filename: datasetFile,
			},
			err: agent.ErrStateNotReady,
		},
		{
			name: "Test File name does not match manifest",
			data: agent.Dataset{
				Dataset:  data,
				Hash:     dataHash,
				Filename: "invalid",
			},
			err: agent.ErrFileNameMismatch,
		},
		{
			name: "Test dataset not declared in manifest",
			data: agent.Dataset{
				Dataset:  data,
				Hash:     dataHash,
				Filename: "invalid",
			},
			err: agent.ErrUndeclaredDataset,
		},
		{
			name: "Test data hash mismatch",
			data: agent.Dataset{
				Filename: datasetFile,
			},
			err: agent.ErrHashMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, "python", python.PyRuntimeKey, python.PyRuntime),
			)

			if tc.err != agent.ErrUndeclaredDataset {
				ctx = agent.IndexToContext(ctx, 0)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t))
			time.Sleep(300 * time.Millisecond)

			if tc.err != agent.ErrStateNotReady {
				_ = svc.Algo(ctx, alg)
				time.Sleep(300 * time.Millisecond)
			}
			err = svc.Data(ctx, tc.data)
			_ = os.RemoveAll("datasets")
			_ = os.RemoveAll("results")
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestResult(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	alg := agent.Algorithm{
		Hash:      algoHash,
		Algorithm: algo,
	}

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(data)

	dataset := agent.Dataset{
		Hash:     dataHash,
		Dataset:  data,
		Filename: datasetFile,
	}

	cases := []struct {
		name string
		err  error
	}{
		{
			name: "Test results not ready",
			err:  agent.ErrResultsNotReady,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, "python", python.PyRuntimeKey, python.PyRuntime),
			)

			ctx = agent.IndexToContext(ctx, 0)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t))
			time.Sleep(300 * time.Millisecond)

			_ = svc.Algo(ctx, alg)
			time.Sleep(300 * time.Millisecond)
			_ = svc.Data(ctx, dataset)
			time.Sleep(300 * time.Millisecond)

			_, err = svc.Result(ctx)
			_ = os.RemoveAll("datasets")
			_ = os.RemoveAll("results")
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

	dataHash := sha3.Sum256(data)

	return agent.Computation{
		ID:              "1",
		Name:            "sample computation",
		Description:     "sample description",
		Datasets:        []agent.Dataset{{Hash: dataHash, UserKey: []byte("key"), Dataset: data, Filename: datasetFile}},
		Algorithm:       agent.Algorithm{Hash: algoHash, UserKey: []byte("key"), Algorithm: algo},
		ResultConsumers: []agent.ResultConsumer{{UserKey: []byte("key")}},
		AgentConfig: agent.AgentConfig{
			Port:        "7002",
			LogLevel:    "debug",
			AttestedTls: false,
		},
	}
}
