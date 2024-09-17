// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/go-sev-guest/client"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/binary"
	"github.com/ultravioletrs/cocos/agent/algorithm/docker"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"github.com/ultravioletrs/cocos/agent/algorithm/wasm"
	"github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/internal"
	"golang.org/x/crypto/sha3"
)

var _ Service = (*agentService)(nil)

const (
	// ReportDataSize is the size of the report data expected by the attestation service.
	ReportDataSize     = 64
	algoFilePermission = 0o700
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")
	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
	// ErrUndeclaredAlgorithm indicates algorithm was not declared in computation manifest.
	ErrUndeclaredDataset = errors.New("dataset not declared in computation manifest")
	// ErrAllManifestItemsReceived indicates no new computation manifest items expected.
	ErrAllManifestItemsReceived = errors.New("all expected manifest Items have been received")
	// ErrUndeclaredConsumer indicates the consumer requesting results in not declared in computation manifest.
	ErrUndeclaredConsumer = errors.New("result consumer is undeclared in computation manifest")
	// ErrResultsNotReady indicates the computation results are not ready.
	ErrResultsNotReady = errors.New("computation results are not yet ready")
	// ErrStateNotReady agent received a request in the wrong state.
	ErrStateNotReady = errors.New("agent not expecting this operation in the current state")
	// ErrHashMismatch provided algorithm/dataset does not match hash in manifest.
	ErrHashMismatch = errors.New("malformed data, hash does not match manifest")
	// ErrFileNameMismatch provided dataset filename does not match filename in manifest.
	ErrFileNameMismatch = errors.New("malformed data, filename does not match manifest")
	// ErrAllResultsConsumed indicates all results have been consumed.
	ErrAllResultsConsumed = errors.New("all results have been consumed by declared consumers")
	// ErrAttestationFailed attestation failed.
	ErrAttestationFailed = errors.New("failed to get raw quote")
)

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
//
//go:generate mockery --name Service --output=mocks --filename agent.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type Service interface {
	Algo(ctx context.Context, algorithm Algorithm) error
	Data(ctx context.Context, dataset Dataset) error
	Result(ctx context.Context) ([]byte, error)
	Attestation(ctx context.Context, reportData [ReportDataSize]byte) ([]byte, error)
}

type agentService struct {
	computation   Computation          // Holds the current computation request details.
	algorithm     algorithm.Algorithm  // Filepath to the algorithm received for the computation.
	result        []byte               // Stores the result of the computation.
	sm            *StateMachine        // Manages the state transitions of the agent service.
	runError      error                // Stores any error encountered during the computation run.
	eventSvc      events.Service       // Service for publishing events related to computation.
	quoteProvider client.QuoteProvider // Provider for generating attestation quotes.
}

var _ Service = (*agentService)(nil)

// New instantiates the agent service implementation.
func New(ctx context.Context, logger *slog.Logger, eventSvc events.Service, cmp Computation, quoteProvider client.QuoteProvider) Service {
	svc := &agentService{
		sm:            NewStateMachine(logger, cmp),
		eventSvc:      eventSvc,
		quoteProvider: quoteProvider,
	}

	go svc.sm.Start(ctx)
	svc.sm.SendEvent(start)
	svc.sm.StateFunctions[Idle] = svc.publishEvent(IdleState.String(), json.RawMessage{})
	svc.sm.StateFunctions[ReceivingManifest] = svc.publishEvent(InProgress.String(), json.RawMessage{})
	svc.sm.StateFunctions[ReceivingAlgorithm] = svc.publishEvent(InProgress.String(), json.RawMessage{})
	svc.sm.StateFunctions[ReceivingData] = svc.publishEvent(InProgress.String(), json.RawMessage{})
	svc.sm.StateFunctions[ConsumingResults] = svc.publishEvent(Ready.String(), json.RawMessage{})
	svc.sm.StateFunctions[Complete] = svc.publishEvent(Completed.String(), json.RawMessage{})
	svc.sm.StateFunctions[Running] = svc.runComputation
	svc.sm.StateFunctions[Failed] = svc.publishEvent(Failed.String(), json.RawMessage{})

	svc.computation = cmp

	svc.sm.SendEvent(manifestReceived)
	return svc
}

func (as *agentService) Algo(ctx context.Context, algo Algorithm) error {
	if as.sm.GetState() != ReceivingAlgorithm {
		return ErrStateNotReady
	}
	if as.algorithm != nil {
		return ErrAllManifestItemsReceived
	}

	hash := sha3.Sum256(algo.Algorithm)

	if hash != as.computation.Algorithm.Hash {
		return ErrHashMismatch
	}

	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current directory: %v", err)
	}

	f, err := os.Create(filepath.Join(currentDir, "algo"))
	if err != nil {
		return fmt.Errorf("error creating algorithm file: %v", err)
	}

	if _, err := f.Write(algo.Algorithm); err != nil {
		return fmt.Errorf("error writing algorithm to file: %v", err)
	}

	if err := os.Chmod(f.Name(), algoFilePermission); err != nil {
		return fmt.Errorf("error changing file permissions: %v", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("error closing file: %v", err)
	}

	algoType := algorithm.AlgorithmTypeFromContext(ctx)
	if algoType == "" {
		algoType = string(algorithm.AlgoTypeBin)
	}

	args := algorithm.AlgorithmArgsFromContext(ctx)

	switch algoType {
	case string(algorithm.AlgoTypeBin):
		as.algorithm = binary.NewAlgorithm(as.sm.logger, as.eventSvc, f.Name(), args)
	case string(algorithm.AlgoTypePython):
		var requirementsFile string
		if len(algo.Requirements) > 0 {
			fr, err := os.CreateTemp("", "requirements.txt")
			if err != nil {
				return fmt.Errorf("error creating requirments file: %v", err)
			}

			if _, err := fr.Write(algo.Requirements); err != nil {
				return fmt.Errorf("error writing requirements to file: %v", err)
			}
			if err := fr.Close(); err != nil {
				return fmt.Errorf("error closing file: %v", err)
			}
			requirementsFile = fr.Name()
		}
		runtime := python.PythonRunTimeFromContext(ctx)
		as.algorithm = python.NewAlgorithm(as.sm.logger, as.eventSvc, runtime, requirementsFile, f.Name(), args)
	case string(algorithm.AlgoTypeWasm):
		as.algorithm = wasm.NewAlgorithm(as.sm.logger, as.eventSvc, f.Name(), args)
	case string(algorithm.AlgoTypeDocker):
		as.algorithm = docker.NewAlgorithm(as.sm.logger, as.eventSvc, f.Name())
	}

	if err := os.Mkdir(algorithm.DatasetsDir, 0o755); err != nil {
		return fmt.Errorf("error creating datasets directory: %v", err)
	}

	if as.algorithm != nil {
		as.sm.SendEvent(algorithmReceived)
	}

	return nil
}

func (as *agentService) Data(ctx context.Context, dataset Dataset) error {
	if as.sm.GetState() != ReceivingData {
		return ErrStateNotReady
	}
	if len(as.computation.Datasets) == 0 {
		return ErrAllManifestItemsReceived
	}

	hash := sha3.Sum256(dataset.Dataset)

	matched := false
	for i, d := range as.computation.Datasets {
		if hash == d.Hash {
			if d.Filename != "" && d.Filename != dataset.Filename {
				return ErrFileNameMismatch
			}

			as.computation.Datasets = slices.Delete(as.computation.Datasets, i, i+1)

			if DecompressFromContext(ctx) {
				if err := internal.UnzipFromMemory(dataset.Dataset, algorithm.DatasetsDir); err != nil {
					return fmt.Errorf("error decompressing dataset: %v", err)
				}
			} else {
				f, err := os.Create(fmt.Sprintf("%s/%s", algorithm.DatasetsDir, dataset.Filename))
				if err != nil {
					return fmt.Errorf("error creating dataset file: %v", err)
				}

				if _, err := f.Write(dataset.Dataset); err != nil {
					return fmt.Errorf("error writing dataset to file: %v", err)
				}
				if err := f.Close(); err != nil {
					return fmt.Errorf("error closing file: %v", err)
				}
			}

			matched = true
			break
		}
	}

	if !matched {
		return ErrUndeclaredDataset
	}

	if len(as.computation.Datasets) == 0 {
		as.sm.SendEvent(dataReceived)
	}

	return nil
}

func (as *agentService) Result(ctx context.Context) ([]byte, error) {
	if as.sm.GetState() != ConsumingResults && as.sm.GetState() != Failed {
		return []byte{}, ErrResultsNotReady
	}
	if len(as.computation.ResultConsumers) == 0 {
		return []byte{}, ErrAllResultsConsumed
	}
	index, ok := IndexFromContext(ctx)
	if !ok {
		return []byte{}, ErrUndeclaredConsumer
	}
	as.computation.ResultConsumers = slices.Delete(as.computation.ResultConsumers, index, index+1)

	if len(as.computation.ResultConsumers) == 0 && as.sm.GetState() == ConsumingResults {
		as.sm.SendEvent(resultsConsumed)
	}

	return as.result, as.runError
}

func (as *agentService) Attestation(ctx context.Context, reportData [ReportDataSize]byte) ([]byte, error) {
	rawQuote, err := as.quoteProvider.GetRawQuote(reportData)
	if err != nil {
		return []byte{}, err
	}

	return rawQuote, nil
}

func (as *agentService) runComputation() {
	as.publishEvent(InProgress.String(), json.RawMessage{})()
	as.sm.logger.Debug("computation run started")
	defer func() {
		if as.runError != nil {
			as.sm.SendEvent(runFailed)
		} else {
			as.sm.SendEvent(runComplete)
		}
	}()

	if err := os.Mkdir(algorithm.ResultsDir, 0o755); err != nil {
		as.runError = fmt.Errorf("error creating results directory: %s", err.Error())
		as.sm.logger.Warn(as.runError.Error())
		as.publishEvent(Failed.String(), json.RawMessage{})()
		return
	}

	defer func() {
		if err := os.RemoveAll(algorithm.ResultsDir); err != nil {
			as.sm.logger.Warn(fmt.Sprintf("error removing results directory and its contents: %s", err.Error()))
		}
		if err := os.RemoveAll(algorithm.DatasetsDir); err != nil {
			as.sm.logger.Warn(fmt.Sprintf("error removing datasets directory and its contents: %s", err.Error()))
		}
	}()

	as.publishEvent(InProgress.String(), json.RawMessage{})()
	if err := as.algorithm.Run(); err != nil {
		as.runError = err
		as.sm.logger.Warn(fmt.Sprintf("failed to run computation: %s", err.Error()))
		as.publishEvent(Failed.String(), json.RawMessage{})()
		return
	}

	results, err := internal.ZipDirectoryToMemory(algorithm.ResultsDir)
	if err != nil {
		as.runError = err
		as.sm.logger.Warn(fmt.Sprintf("failed to zip results: %s", err.Error()))
		as.publishEvent(Failed.String(), json.RawMessage{})()
		return
	}

	as.publishEvent(Completed.String(), json.RawMessage{})()

	as.result = results
}

func (as *agentService) publishEvent(status string, details json.RawMessage) func() {
	st := as.sm.GetState().String()
	return func() {
		if err := as.eventSvc.SendEvent(st, status, details); err != nil {
			as.sm.logger.Warn(err.Error())
		}
	}
}
