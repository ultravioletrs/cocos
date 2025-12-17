// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	mglog "github.com/absmach/supermq/logger"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
	runnerpb "github.com/ultravioletrs/cocos/agent/runner"
	"github.com/ultravioletrs/cocos/agent/statemachine"
	smmocks "github.com/ultravioletrs/cocos/agent/statemachine/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	runnermocks "github.com/ultravioletrs/cocos/pkg/clients/grpc/runner/mocks"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	algoPath = "../test/manual/algo/lin_reg.py"
	reqPath  = "../test/manual/algo/requirements.txt"
	dataPath = "../test/manual/data/iris.csv"
)

const datasetFile = "iris.csv"

func TestAlgo(t *testing.T) {
	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)
	vtpm.ExternalTPM = &vtpm.DummyRWC{}

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

			events := new(mocks.Service)
			events.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			client := new(MockAttestationClient)
			runnerCli := new(runnermocks.Client)
			runnerCli.On("Run", mock.Anything, mock.Anything).Return(&runnerpb.RunResponse{}, nil)
			svc := New(ctx, mglog.NewMock(), events, client, runnerCli, 0)

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
	algo, err := os.ReadFile(algoPath)
	require.NoError(t, err)

	algoHash := sha3.Sum256(algo)
	vtpm.ExternalTPM = &vtpm.DummyRWC{}

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

			events := new(mocks.Service)
			events.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

			if tc.err != ErrUndeclaredDataset {
				ctx = IndexToContext(ctx, 0)
			}

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			client := new(MockAttestationClient)
			runnerCli := new(runnermocks.Client)
			runnerCli.On("Run", mock.Anything, mock.Anything).Return(&runnerpb.RunResponse{}, nil)
			svc := New(ctx, mglog.NewMock(), events, client, runnerCli, 0)

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
		events := new(mocks.Service)
		events.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, "python", python.PyRuntimeKey, python.PyRuntime),
			)

			if tc.ctxSetup != nil {
				ctx = tc.ctxSetup(ctx)
			}

			client := new(MockAttestationClient)
			runnerCli := new(runnermocks.Client)

			sm := new(smmocks.StateMachine)
			sm.On("Start", ctx).Return(nil)
			sm.On("GetState").Return(tc.state)
			sm.On("SendEvent", mock.Anything).Return()

			svc := &agentService{
				sm:                sm,
				eventSvc:          events,
				attestationClient: client,
				runnerClient:      runnerCli,
				computation:       testComputation(t),
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
	client := new(MockAttestationClient)

	cases := []struct {
		name       string
		reportData [quoteprovider.Nonce]byte
		nonce      [vtpm.Nonce]byte
		rawQuote   []uint8
		platform   attestation.PlatformType
		err        error
	}{
		{
			name:       "Test SNP attestation successful",
			reportData: generateReportData(),
			nonce:      [32]byte{},
			rawQuote:   make([]uint8, 0),
			platform:   attestation.SNP,
			err:        nil,
		},
		{
			name:       "Test SNP attestation failed",
			reportData: generateReportData(),
			nonce:      [32]byte{},
			rawQuote:   nil,
			platform:   attestation.SNP,
			err:        ErrAttestationFailed,
		},
		{
			name:       "Test vTPM attestation successful",
			reportData: generateReportData(),
			nonce:      [32]byte{},
			rawQuote:   make([]uint8, 0),
			platform:   attestation.VTPM,
			err:        nil,
		},
		{
			name:       "Test vTPM attestation failed",
			reportData: generateReportData(),
			nonce:      [32]byte{},
			rawQuote:   nil,
			platform:   attestation.VTPM,
			err:        ErrAttestationVTpmFailed,
		},
		{
			name:       "Test SNP-vTPM attestation successful",
			reportData: generateReportData(),
			nonce:      [32]byte{},
			rawQuote:   make([]uint8, 0),
			platform:   attestation.SNPvTPM,
			err:        nil,
		},
		{
			name:       "Test SNP-vTPM attestation failed",
			reportData: generateReportData(),
			nonce:      [32]byte{},
			rawQuote:   nil,
			platform:   attestation.SNPvTPM,
			err:        ErrAttestationVTpmFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := new(mocks.Service)
			events.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

			ctx := metadata.NewIncomingContext(context.Background(),
				metadata.Pairs(algorithm.AlgoTypeKey, "python", python.PyRuntimeKey, python.PyRuntime),
			)
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			getQuote := client.On("GetAttestation", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.rawQuote, tc.err)
			if tc.err != ErrAttestationFailed && tc.err != ErrAttestationVTpmFailed {
				getQuote = client.On("GetAttestation", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.nonce[:], nil)
			}
			defer getQuote.Unset()

			runnerCli := new(runnermocks.Client)
			svc := New(ctx, mglog.NewMock(), events, client, runnerCli, 0)
			time.Sleep(300 * time.Millisecond)
			_, err := svc.Attestation(ctx, tc.reportData, tc.nonce, tc.platform)
			assert.True(t, errors.Contains(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}

func TestAzureAttestationToken(t *testing.T) {
	client := new(MockAttestationClient)
	cases := []struct {
		name  string
		nonce [vtpm.Nonce]byte
		token []byte
		err   error
	}{
		{
			name:  "Azure token fetch successful",
			nonce: [32]byte{1, 2, 3}, // any test nonce
			token: []byte("mockToken"),
			err:   nil,
		},
		{
			name:  "Azure token fetch failed",
			nonce: [32]byte{4, 5, 6},
			token: []byte{},
			err:   ErrAttestationType,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := new(mocks.Service)
			events.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

			client.On("GetAzureToken", mock.Anything, tc.nonce).Return(tc.token, tc.err)

			ctx := context.Background()

			runnerCli := new(runnermocks.Client)
			svc := New(ctx, mglog.NewMock(), events, client, runnerCli, 0)

			_, err := svc.AzureAttestationToken(ctx, tc.nonce)
			assert.True(t, errors.Contains(err, tc.err), "expected error %v, got %v", tc.err, err)
		})
	}
}

func generateReportData() [quoteprovider.Nonce]byte {
	bytes := make([]byte, quoteprovider.Nonce)
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

func TestStopComputation(t *testing.T) {
	cases := []struct {
		name        string
		setupDirs   bool
		setupAlgo   bool
		algoStopErr error
		expectedErr error
	}{
		{
			name:        "Stop computation successfully",
			setupDirs:   true,
			setupAlgo:   true,
			algoStopErr: nil,
			expectedErr: nil,
		},
		{
			name:        "Stop computation with algorithm stop error",
			setupDirs:   true,
			setupAlgo:   true,
			algoStopErr: fmt.Errorf("algorithm stop failed"),
			expectedErr: nil, // Warn only
		},
		// We log warnings but don't return error in StopComputation in new implementation for Stop failure.
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := new(mocks.Service)
			events.On("SendEvent", mock.Anything, "Stopped", "Stopped", mock.Anything).Return()

			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			client := new(MockAttestationClient)
			runnerCli := new(runnermocks.Client)

			// Mock Stop call
			var stopErr error
			if tc.algoStopErr != nil {
				stopErr = tc.algoStopErr
			}
			runnerCli.On("Stop", mock.Anything, mock.Anything).Return(&emptypb.Empty{}, stopErr)

			svc := New(ctx, mglog.NewMock(), events, client, runnerCli, 0).(*agentService)

			svc.computation = Computation{
				ID:   "test-computation",
				Name: "test",
			}

			if tc.setupDirs {
				err := os.MkdirAll(algorithm.DatasetsDir, 0o755)
				require.NoError(t, err)
				err = os.MkdirAll(algorithm.ResultsDir, 0o755)
				require.NoError(t, err)
			}

			// Use real dirs for test
			// algorithm.DatasetsDir refers to global var?
			// "github.com/ultravioletrs/cocos/agent/algorithm"
			// It uses hardcoded path "datasets" and "results" in current dir.
			// Tests create them in current dir.

			err := svc.StopComputation(ctx)

			if tc.expectedErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, ReceivingManifest, svc.sm.GetState())
			assert.Nil(t, svc.result)
			assert.Nil(t, svc.runError)
			assert.False(t, svc.resultsConsumed)

			events.AssertExpectations(t)

			_ = os.RemoveAll(algorithm.DatasetsDir)
			_ = os.RemoveAll(algorithm.ResultsDir)
		})
	}
}

func TestStopComputationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	algo := []byte("#!/bin/bash\necho 'test algorithm'")
	algoHash := sha3.Sum256(algo)

	testDir := "test_integration"
	err := os.MkdirAll(testDir, 0o755)
	require.NoError(t, err)
	defer os.RemoveAll(testDir)

	algoFile := filepath.Join(testDir, "test_algo")
	err = os.WriteFile(algoFile, algo, 0o755)
	require.NoError(t, err)

	events := new(mocks.Service)
	events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(algorithm.AlgoTypeKey, "bin"),
	)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client := new(MockAttestationClient)
	runnerCli := new(runnermocks.Client)
	runnerCli.On("Run", mock.Anything, mock.Anything).Return(&runnerpb.RunResponse{}, nil)
	runnerCli.On("Stop", mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil)

	svc := New(ctx, mglog.NewMock(), events, client, runnerCli, 0)

	computation := Computation{
		ID:   "integration-test",
		Name: "Integration Test",
		Algorithm: Algorithm{
			Hash:      algoHash,
			Algorithm: algo,
		},
	}

	err = svc.InitComputation(ctx, computation)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = svc.Algo(ctx, Algorithm{
		Hash:      algoHash,
		Algorithm: algo,
	})
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = svc.StopComputation(ctx)
	assert.NoError(t, err)

	assert.Equal(t, "ReceivingManifest", svc.State())
}

func TestStopComputationConcurrent(t *testing.T) {
	events := new(mocks.Service)
	events.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	client := new(MockAttestationClient)
	runnerCli := new(runnermocks.Client)
	runnerCli.On("Stop", mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil)

	svc := New(ctx, mglog.NewMock(), events, client, runnerCli, 0)

	svc.(*agentService).computation = Computation{
		ID:   "concurrent-test",
		Name: "Concurrent Test",
	}

	const numGoroutines = 10
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			err := svc.StopComputation(ctx)
			errChan <- err
		}()
	}

	var errors []error
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		if err != nil {
			errors = append(errors, err)
		}
	}

	assert.True(t, len(errors) < numGoroutines, "All StopComputation calls failed")
}

