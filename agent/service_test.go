// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
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
	agentevents "github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
	runnerpb "github.com/ultravioletrs/cocos/agent/runner"
	"github.com/ultravioletrs/cocos/agent/statemachine"
	smmocks "github.com/ultravioletrs/cocos/agent/statemachine/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	runnermocks "github.com/ultravioletrs/cocos/pkg/clients/grpc/runner/mocks"
	"github.com/ultravioletrs/cocos/pkg/oci"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

type MockOCIClient struct {
	mock.Mock
}

func (m *MockOCIClient) PullAndDecrypt(ctx context.Context, source oci.ResourceSource, destDir string) error {
	args := m.Called(ctx, source, destDir)
	return args.Error(0)
}

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
		reportData [vtpm.SEVNonce]byte
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

func generateReportData() [vtpm.SEVNonce]byte {
	bytes := make([]byte, vtpm.SEVNonce)
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

// newTestAgentService creates a minimal agentService for direct method testing.
func newTestAgentService(sm statemachine.StateMachine, eventSvc agentevents.Service) *agentService {
	return &agentService{
		logger:   slog.Default(),
		eventSvc: eventSvc,
		sm:       sm,
	}
}

func TestDownloadAndDecryptResource(t *testing.T) {
	eventsSvc := new(mocks.Service)
	eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

	sm := &smmocks.StateMachine{}
	sm.On("SendEvent", mock.Anything).Return().Maybe()

	svc := newTestAgentService(sm, eventsSvc)

	ctx := context.Background()

	t.Run("unsupported URL format no type", func(t *testing.T) {
		source := &ResourceSource{URL: "http://unsupported-format"}
		_, err := svc.downloadAndDecryptResource(ctx, source, "algorithm")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported source URL format")
	})

	t.Run("ftp URL unsupported format", func(t *testing.T) {
		source := &ResourceSource{URL: "ftp://some-server/file"}
		_, err := svc.downloadAndDecryptResource(ctx, source, "algorithm")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported source URL format")
	})

	t.Run("unsupported explicit source type", func(t *testing.T) {
		source := &ResourceSource{Type: "s3-bucket", URL: "s3://mybucket/algo"}
		_, err := svc.downloadAndDecryptResource(ctx, source, "algorithm")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported source type: s3-bucket")
	})

	t.Run("docker:// URL inferred as oci-image routes to skopeo", func(t *testing.T) {
		// This exercises the oci-image path; will fail at skopeo step
		source := &ResourceSource{URL: "docker://invalid.example.com/algo:latest"}
		_, err := svc.downloadAndDecryptResource(ctx, source, "algorithm")
		require.Error(t, err)
		// Should be a skopeo or OCI error, not an "unsupported" error
		assert.NotContains(t, err.Error(), "unsupported source URL format")
	})

	t.Run("oci: URL inferred as oci-image routes to skopeo", func(t *testing.T) {
		source := &ResourceSource{URL: "oci:some-local-dir"}
		_, err := svc.downloadAndDecryptResource(ctx, source, "algorithm")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "unsupported source URL format")
	})

	t.Run("explicit oci-image type routes to skopeo", func(t *testing.T) {
		source := &ResourceSource{Type: "oci-image", URL: "docker://invalid.example.com/algo:latest"}
		_, err := svc.downloadAndDecryptResource(ctx, source, "algorithm")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "unsupported source type")
	})

	t.Run("dataset resource type with oci-image", func(t *testing.T) {
		source := &ResourceSource{Type: "oci-image", URL: "docker://invalid.example.com/data:latest"}
		_, err := svc.downloadAndDecryptResource(ctx, source, "dataset")
		require.Error(t, err)
	})
}

func TestDownloadAlgorithmIfRemote(t *testing.T) {
	t.Run("no source configured - no-op, waits for direct upload", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		// No SendEvent expected — just the no-op path

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{} // Algorithm.Source == nil

		svc.downloadAlgorithmIfRemote(ReceivingAlgorithm)
		assert.Nil(t, svc.runError)
		sm.AssertExpectations(t)
	})

	t.Run("source set but KBS disabled - no-op", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{
			Algorithm: Algorithm{
				Source: &ResourceSource{URL: "docker://registry/algo:latest"},
			},
			KBS: KBSConfig{Enabled: false},
		}

		svc.downloadAlgorithmIfRemote(ReceivingAlgorithm)
		assert.Nil(t, svc.runError)
		sm.AssertExpectations(t)
	})

	t.Run("source + KBS enabled - download fails, sends RunFailed", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		sm.On("SendEvent", RunFailed).Return().Once()

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{
			Algorithm: Algorithm{
				Source: &ResourceSource{
					Type: "oci-image",
					URL:  "docker://invalid.example.com/algo:latest",
				},
			},
			KBS: KBSConfig{Enabled: true, URL: "https://kbs.example.com"},
		}

		svc.downloadAlgorithmIfRemote(ReceivingAlgorithm)
		assert.NotNil(t, svc.runError)
		assert.Contains(t, svc.runError.Error(), "failed to download and decrypt algorithm")
		sm.AssertExpectations(t)
	})

	t.Run("unsupported URL format - download fails, sends RunFailed", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		sm.On("SendEvent", RunFailed).Return().Once()

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{
			Algorithm: Algorithm{
				Source: &ResourceSource{
					URL: "http://unsupported-format/algo",
				},
			},
			KBS: KBSConfig{Enabled: true},
		}

		svc.downloadAlgorithmIfRemote(ReceivingAlgorithm)
		assert.NotNil(t, svc.runError)
		sm.AssertExpectations(t)
	})
}

func TestDownloadDatasetsIfRemote(t *testing.T) {
	t.Run("no datasets with remote sources - no-op", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}

		svc := newTestAgentService(sm, eventsSvc)
		// Dataset with no Source
		dataHash := sha3.Sum256([]byte("testdata"))
		svc.computation = Computation{
			Datasets: []Dataset{
				{Hash: dataHash, Filename: "data.csv"},
			},
			KBS: KBSConfig{Enabled: true},
		}

		svc.downloadDatasetsIfRemote(ReceivingData)
		// No RunFailed event, no DataReceived event
		sm.AssertExpectations(t)
	})

	t.Run("no datasets at all - no-op", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{
			Datasets: []Dataset{},
			KBS:      KBSConfig{Enabled: true},
		}

		svc.downloadDatasetsIfRemote(ReceivingData)
		sm.AssertExpectations(t)
	})

	t.Run("KBS disabled even with source - no-op", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{
			Datasets: []Dataset{
				{
					Filename: "data.csv",
					Source:   &ResourceSource{URL: "docker://registry/data:latest"},
				},
			},
			KBS: KBSConfig{Enabled: false},
		}

		svc.downloadDatasetsIfRemote(ReceivingData)
		sm.AssertExpectations(t)
	})

	t.Run("remote dataset + KBS enabled - download fails, sends RunFailed", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		sm.On("SendEvent", RunFailed).Return().Once()

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{
			Datasets: []Dataset{
				{
					Filename: "data.csv",
					Source: &ResourceSource{
						Type: "oci-image",
						URL:  "docker://invalid.example.com/data:latest",
					},
				},
			},
			KBS: KBSConfig{Enabled: true, URL: "https://kbs.example.com"},
		}

		svc.downloadDatasetsIfRemote(ReceivingData)
		sm.AssertExpectations(t)
	})

	t.Run("unsupported URL fails - sends RunFailed", func(t *testing.T) {
		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		sm.On("SendEvent", RunFailed).Return().Once()

		svc := newTestAgentService(sm, eventsSvc)
		svc.computation = Computation{
			Datasets: []Dataset{
				{
					Filename: "data.csv",
					Source: &ResourceSource{
						URL: "ftp://unsupported/data",
					},
				},
			},
			KBS: KBSConfig{Enabled: true},
		}

		svc.downloadDatasetsIfRemote(ReceivingData)
		sm.AssertExpectations(t)
	})
}

func TestRunComputation(t *testing.T) {
	// Helper to set up a temp working directory and restore CWD afterwards.
	withTempDir := func(t *testing.T) (tmpDir string, restore func()) {
		t.Helper()
		origDir, err := os.Getwd()
		require.NoError(t, err)
		tmpDir = t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))
		return tmpDir, func() { _ = os.Chdir(origDir) }
	}

	t.Run("algo file not found sends RunFailed", func(t *testing.T) {
		_, restore := withTempDir(t)
		defer restore()

		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		sm.On("SendEvent", RunFailed).Return().Once()

		svc := newTestAgentService(sm, eventsSvc)
		// No algo file exists – runComputation should hit the ReadFile error path.
		svc.runComputation(Running)

		assert.Error(t, svc.runError)
		assert.Contains(t, svc.runError.Error(), "failed to read algo file")
		sm.AssertExpectations(t)
	})

	t.Run("runner client returns error sends RunFailed", func(t *testing.T) {
		_, restore := withTempDir(t)
		defer restore()

		// Write a dummy algo file so ReadFile succeeds.
		require.NoError(t, os.WriteFile("algo", []byte("#!/bin/sh\necho ok\n"), 0o755))

		runnerCli := new(runnermocks.Client)
		runnerCli.On("Run", mock.Anything, mock.Anything).Return((*runnerpb.RunResponse)(nil), fmt.Errorf("runner unavailable"))

		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		sm.On("SendEvent", RunFailed).Return().Once()

		svc := newTestAgentService(sm, eventsSvc)
		svc.runnerClient = runnerCli

		svc.runComputation(Running)

		assert.Error(t, svc.runError)
		assert.Contains(t, svc.runError.Error(), "runner unavailable")
		sm.AssertExpectations(t)
	})

	t.Run("runner returns non-empty error field sends RunFailed", func(t *testing.T) {
		_, restore := withTempDir(t)
		defer restore()

		require.NoError(t, os.WriteFile("algo", []byte("#!/bin/sh\necho ok\n"), 0o755))

		runnerCli := new(runnermocks.Client)
		runnerCli.On("Run", mock.Anything, mock.Anything).Return(&runnerpb.RunResponse{Error: "computation crashed"}, nil)

		eventsSvc := new(mocks.Service)
		eventsSvc.EXPECT().SendEvent(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		sm := &smmocks.StateMachine{}
		sm.On("SendEvent", RunFailed).Return().Once()

		svc := newTestAgentService(sm, eventsSvc)
		svc.runnerClient = runnerCli

		svc.runComputation(Running)

		assert.Error(t, svc.runError)
		assert.Contains(t, svc.runError.Error(), "computation crashed")
		sm.AssertExpectations(t)
	})
}

func TestIMAMeasurements(t *testing.T) {
	t.Run("error when IMA measurements file does not exist in non-SGX environment", func(t *testing.T) {
		// In a regular test environment (non-SGX), the IMA measurements file
		// at /sys/kernel/security/integrity/ima/ascii_runtime_measurements won't exist.
		// Verify our error handling works correctly.
		origPath := ImaMeasurementsFilePath
		ImaMeasurementsFilePath = "/non/existent/path"
		defer func() { ImaMeasurementsFilePath = origPath }()

		eventsSvc := new(mocks.Service)
		eventsSvc.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
		sm := &smmocks.StateMachine{}

		svc := newTestAgentService(sm, eventsSvc)

		data, pcr10, err := svc.IMAMeasurements(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error reading Linux IMA measurements file")
		assert.Nil(t, data)
		assert.Nil(t, pcr10)
	})

	t.Run("successful reading of IMA measurements", func(t *testing.T) {
		tempFile := filepath.Join(t.TempDir(), "ima_measurements")
		content := []byte("10 sha1:0000000000000000000000000000000000000000 ima-ng sha256:0000000000000000000000000000000000000000000000000000000000000000 /usr/bin/python3\n")
		err := os.WriteFile(tempFile, content, 0o644)
		require.NoError(t, err)
		vtpm.ExternalTPM = &vtpm.DummyRWC{}

		origPath := ImaMeasurementsFilePath
		ImaMeasurementsFilePath = tempFile
		defer func() { ImaMeasurementsFilePath = origPath }()

		eventsSvc := new(mocks.Service)
		eventsSvc.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
		sm := &smmocks.StateMachine{}
		svc := newTestAgentService(sm, eventsSvc)

		data, pcr10, err := svc.IMAMeasurements(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, content, data)
		assert.NotEmpty(t, pcr10)
	})
}

func TestDownloadAlgorithmIfRemote_Success(t *testing.T) {
	// Skip this test in short mode as it might involve more setup if we were using real OCI
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	defer func() { require.NoError(t, os.Chdir(origDir)) }()

	eventsSvc := new(mocks.Service)
	eventsSvc.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	sm := &smmocks.StateMachine{}
	sm.On("SendEvent", AlgorithmReceived).Return().Once()

	mockOCI := new(MockOCIClient)
	algoContent := []byte("print('hello')")
	mockOCI.On("PullAndDecrypt", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		destDir := args.String(2)
		setupMinimalOCI(t, destDir, "main.py", string(algoContent))
	}).Return(nil)

	svc := newTestAgentService(sm, eventsSvc)
	svc.ociClient = mockOCI

	algoContent = []byte("print('hello')")
	algoHash := sha3.Sum256(algoContent)

	svc.computation = Computation{
		Algorithm: Algorithm{
			Hash:     algoHash,
			AlgoType: "python",
			Source: &ResourceSource{
				Type: "oci-image",
				URL:  "docker://test/image",
			},
		},
		KBS: KBSConfig{Enabled: true},
	}

	// We need to bypass oci.ExtractAlgorithm by manually creating what it would create
	// OR use a real-enough looking OCI layout.
	// Since we can't easily mock oci.ExtractAlgorithm, we'll try to provide a minimal OCI layout
	// so that oci.ExtractAlgorithm doesn't fail.

	svc.downloadAlgorithmIfRemote(ReceivingAlgorithm)

	assert.Nil(t, svc.runError)
	assert.True(t, svc.algoReceived)
	sm.AssertExpectations(t)
	mockOCI.AssertExpectations(t)
}

func setupMinimalOCI(t *testing.T, ociDir, filename, content string) {
	t.Helper()
	blobsDir := filepath.Join(ociDir, "blobs", "sha256")
	require.NoError(t, os.MkdirAll(blobsDir, 0o755))

	layerPath := filepath.Join(blobsDir, "layer123")
	layerFile, err := os.Create(layerPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(layerFile)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: filename,
		Mode: 0o755,
		Size: int64(len(content)),
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, err = tw.Write([]byte(content))
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	require.NoError(t, layerFile.Close())

	manifest := struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}{
		Layers: []struct {
			Digest string `json:"digest"`
		}{{Digest: "sha256:layer123"}},
	}
	manifestData, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

	index := oci.OCIIndex{
		SchemaVersion: 2,
		Manifests: []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int    `json:"size"`
		}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
	}
	indexData, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))
}

func TestDownloadDatasetsIfRemote_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	defer func() { require.NoError(t, os.Chdir(origDir)) }()

	eventsSvc := new(mocks.Service)
	eventsSvc.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	sm := &smmocks.StateMachine{}
	sm.On("SendEvent", DataReceived).Return().Once()

	mockOCI := new(MockOCIClient)
	dataContent := []byte("a,b,c\n1,2,3")
	mockOCI.On("PullAndDecrypt", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		destDir := args.String(2)
		setupMinimalOCI(t, destDir, "data.csv", string(dataContent))
	}).Return(nil)

	svc := newTestAgentService(sm, eventsSvc)
	svc.ociClient = mockOCI

	dataContent = []byte("a,b,c\n1,2,3")
	dataHash := sha3.Sum256(dataContent)

	svc.computation = Computation{
		Datasets: []Dataset{
			{
				Filename: "data.csv",
				Hash:     dataHash,
				Source: &ResourceSource{
					Type: "oci-image",
					URL:  "docker://test/image",
				},
			},
		},
		KBS: KBSConfig{Enabled: true},
	}

	err := os.MkdirAll(algorithm.DatasetsDir, 0o755)
	require.NoError(t, err)

	svc.downloadDatasetsIfRemote(ReceivingData)

	assert.Nil(t, svc.runError)
	assert.Len(t, svc.computation.Datasets, 0)
	sm.AssertExpectations(t)
	mockOCI.AssertExpectations(t)
}
