// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent_test

import (
	"context"
	"crypto/rand"
	"log"
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
	amocks "github.com/ultravioletrs/cocos/agent/mocks"
	"github.com/ultravioletrs/cocos/agent/quoteprovider"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/metadata"
)

var (
	algoPath = "../test/manual/algo/lin_reg.py"
	reqPath  = "../test/manual/algo/requirements.txt"
	dataPath = "../test/manual/data/iris.csv"
)

const datasetFile = "iris.csv"

func TestAlgo(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	qp, err := quoteprovider.GetQuoteProvider()
	require.NoError(t, err)

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	reqFile, err := os.ReadFile(reqPath)
	require.NoError(t, err)

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
			name: "Test Algo successfully with requirements file",
			algo: agent.Algorithm{
				Algorithm:    algo,
				Hash:         algoHash,
				Requirements: reqFile,
			},
			algoType: "python",
			err:      nil,
		},
		{
			name: "Test Algo type binary successfully",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "bin",
			err:      nil,
		},
		{
			name: "Test Algo type wasm successfully",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "wasm",
			err:      nil,
		},
		{
			name: "Test Algo type docker successfully",
			algo: agent.Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "docker",
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
			err = os.RemoveAll("datasets")
			require.NoError(t, err)

			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, tc.algoType, python.PyRuntimeKey, python.PyRuntime),
			)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t), qp)

			time.Sleep(300 * time.Millisecond)

			err = svc.Algo(ctx, tc.algo)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestData(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	qp, err := quoteprovider.GetQuoteProvider()
	require.NoError(t, err)

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
				Filename: datasetFile,
			},
			err: agent.ErrUndeclaredDataset,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(
					algorithm.AlgoTypeKey, "python",
					python.PyRuntimeKey, python.PyRuntime),
			)

			if tc.err != agent.ErrUndeclaredDataset {
				ctx = agent.IndexToContext(ctx, 0)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			comp := testComputation(t)

			svc := agent.New(ctx, mglog.NewMock(), events, comp, qp)
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

	qp, err := quoteprovider.GetQuoteProvider()
	require.NoError(t, err)

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

			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t), qp)

			time.Sleep(300 * time.Millisecond)
			_, err := svc.Result(ctx)

			_ = os.RemoveAll("datasets")
			_ = os.RemoveAll("results")
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestAttestation(t *testing.T) {
	events := new(mocks.Service)
	qp := new(amocks.QuoteProvider)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	cases := []struct {
		name       string
		reportData [agent.ReportDataSize]byte
		rawQuote   []uint8
		err        error
	}{
		{
			name:       "Test attestation successful",
			reportData: generateReportData(),
			rawQuote:   make([]uint8, 0),
			err:        nil,
		},
		{
			name:       "Test attestation failed",
			reportData: generateReportData(),
			rawQuote:   nil,
			err:        agent.ErrAttestationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, "python", python.PyRuntimeKey, python.PyRuntime),
			)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			getQuote := qp.On("GetRawQuote", mock.Anything).Return(tc.rawQuote, tc.err)
			if tc.err != agent.ErrAttestationFailed {
				getQuote = qp.On("GetRawQuote", mock.Anything).Return(tc.reportData, nil)
			}
			defer getQuote.Unset()

			svc := agent.New(ctx, mglog.NewMock(), events, testComputation(t), qp)
			time.Sleep(300 * time.Millisecond)
			_, err := svc.Attestation(ctx, tc.reportData)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func generateReportData() [agent.ReportDataSize]byte {
	bytes := make([]byte, agent.ReportDataSize)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}
	return [64]byte(bytes)
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
