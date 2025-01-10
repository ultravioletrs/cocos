// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

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
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
	"github.com/ultravioletrs/cocos/agent/statemachine"
	smmocks "github.com/ultravioletrs/cocos/agent/statemachine/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	mocks2 "github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider/mocks"
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

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
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
		algo     Algorithm
		algoType string
	}{
		{
			name: "Test Algo successfully",
			algo: Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "python",
			err:      nil,
		},
		{
			name: "Test Algo successfully with requirements file",
			algo: Algorithm{
				Algorithm:    algo,
				Hash:         algoHash,
				Requirements: reqFile,
			},
			algoType: "python",
			err:      nil,
		},
		{
			name: "Test Algo type binary successfully",
			algo: Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "bin",
			err:      nil,
		},
		{
			name: "Test Algo type wasm successfully",
			algo: Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "wasm",
			err:      nil,
		},
		{
			name: "Test Algo type docker successfully",
			algo: Algorithm{
				Algorithm: algo,
				Hash:      algoHash,
			},
			algoType: "docker",
			err:      nil,
		},
		{
			name:     "Test algo hash mismatch",
			algo:     Algorithm{},
			algoType: "python",
			err:      ErrHashMismatch,
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
			svc := New(ctx, mglog.NewMock(), events, qp)

			err := svc.InitComputation(ctx, testComputation(t))
			require.NoError(t, err)

			time.Sleep(300 * time.Millisecond)

			err = svc.Algo(ctx, tc.algo)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
			t.Cleanup(func() {
				err = os.RemoveAll("venv")
				err = os.RemoveAll("algo")
				err = os.RemoveAll("datasets")
			})
		})
	}
}

func TestData(t *testing.T) {
	events := new(mocks.Service)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	qp, err := quoteprovider.GetQuoteProvider()
	require.NoError(t, err)

	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	alg := Algorithm{
		Hash:      algoHash,
		Algorithm: algo,
	}

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(data)

	cases := []struct {
		name string
		data Dataset
		err  error
	}{
		{
			name: "Test data successfully",
			data: Dataset{
				Hash:     dataHash,
				Dataset:  data,
				Filename: datasetFile,
			},
		},
		{
			name: "Test State not ready",
			data: Dataset{
				Dataset:  data,
				Hash:     dataHash,
				Filename: datasetFile,
			},
			err: ErrStateNotReady,
		},
		{
			name: "Test File name does not match manifest",
			data: Dataset{
				Dataset:  data,
				Hash:     dataHash,
				Filename: "invalid",
			},
			err: ErrFileNameMismatch,
		},
		{
			name: "Test dataset not declared in manifest",
			data: Dataset{
				Filename: datasetFile,
			},
			err: ErrUndeclaredDataset,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(
					algorithm.AlgoTypeKey, "python",
					python.PyRuntimeKey, python.PyRuntime),
			)

			if tc.err != ErrUndeclaredDataset {
				ctx = IndexToContext(ctx, 0)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			svc := New(ctx, mglog.NewMock(), events, qp)

			err := svc.InitComputation(ctx, testComputation(t))
			require.NoError(t, err)

			time.Sleep(300 * time.Millisecond)

			if tc.err != ErrStateNotReady {
				err = svc.Algo(ctx, alg)
				require.NoError(t, err)
				time.Sleep(300 * time.Millisecond)
			}
			err = svc.Data(ctx, tc.data)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
			t.Cleanup(func() {
				_ = os.RemoveAll("datasets")
				_ = os.RemoveAll("results")
				err = os.RemoveAll("venv")
				err = os.RemoveAll("algo")
			})
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
		name     string
		err      error
		setup    func(svc *agentService)
		ctxSetup func(ctx context.Context) context.Context
		state    statemachine.State
	}{
		{
			name: "Test results not ready",
			err:  ErrResultsNotReady,
			setup: func(svc *agentService) {
			},
			state: Running,
		},
		{
			name: "Test undeclared consumer",
			err:  ErrUndeclaredConsumer,
			setup: func(svc *agentService) {
				svc.computation.ResultConsumers = []ResultConsumer{{UserKey: []byte("user")}}
			},
			ctxSetup: func(ctx context.Context) context.Context {
				return ctx
			},
			state: ConsumingResults,
		},
		{
			name: "Test results consumed and event sent",
			err:  nil,
			setup: func(svc *agentService) {
				svc.computation.ResultConsumers = []ResultConsumer{{UserKey: []byte("key")}}
			},
			ctxSetup: func(ctx context.Context) context.Context {
				return IndexToContext(ctx, 0)
			},
			state: ConsumingResults,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, "python", python.PyRuntimeKey, python.PyRuntime),
			)

			if tc.ctxSetup != nil {
				ctx = tc.ctxSetup(ctx)
			}

			sm := new(smmocks.StateMachine)
			sm.On("Start", ctx).Return(nil)
			sm.On("GetState").Return(tc.state)
			sm.On("SendEvent", mock.Anything).Return()

			svc := &agentService{
				sm:            sm,
				eventSvc:      events,
				quoteProvider: qp,
				computation:   testComputation(t),
			}

			go func() {
				if err := svc.sm.Start(ctx); err != nil {
					t.Errorf("Error starting state machine: %v", err)
				}
			}()
			tc.setup(svc)
			_, err := svc.Result(ctx)
			t.Cleanup(func() {
				_ = os.RemoveAll("datasets")
				_ = os.RemoveAll("results")
			})
			assert.ErrorIs(t, err, tc.err, "expected %v, got %v", tc.err, err)
		})
	}
}

func TestAttestation(t *testing.T) {
	events := new(mocks.Service)
	qp := new(mocks2.QuoteProvider)

	evCall := events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	defer evCall.Unset()

	cases := []struct {
		name       string
		reportData [ReportDataSize]byte
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
			err:        ErrAttestationFailed,
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
			if tc.err != ErrAttestationFailed {
				getQuote = qp.On("GetRawQuote", mock.Anything).Return(tc.reportData, nil)
			}
			defer getQuote.Unset()

			svc := New(ctx, mglog.NewMock(), events, qp)
			time.Sleep(300 * time.Millisecond)
			_, err := svc.Attestation(ctx, tc.reportData)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func generateReportData() [ReportDataSize]byte {
	bytes := make([]byte, ReportDataSize)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}
	return [64]byte(bytes)
}

func testComputation(t *testing.T) Computation {
	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)

	data, err := os.ReadFile(dataPath)
	require.NoError(t, err)

	dataHash := sha3.Sum256(data)

	return Computation{
		ID:              "1",
		Name:            "sample computation",
		Description:     "sample description",
		Datasets:        []Dataset{{Hash: dataHash, UserKey: []byte("key"), Dataset: data, Filename: datasetFile}},
		Algorithm:       Algorithm{Hash: algoHash, UserKey: []byte("key"), Algorithm: algo},
		ResultConsumers: []ResultConsumer{{UserKey: []byte("key")}},
	}
}
