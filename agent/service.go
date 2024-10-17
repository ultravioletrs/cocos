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
	sync "sync"

	"github.com/google/go-sev-guest/client"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/binary"
	"github.com/ultravioletrs/cocos/agent/algorithm/docker"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"github.com/ultravioletrs/cocos/agent/algorithm/wasm"
	"github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/agent/statemachine"
	"github.com/ultravioletrs/cocos/internal"
	"golang.org/x/crypto/sha3"
)

var _ Service = (*agentService)(nil)

//go:generate stringer -type=AgentState
type AgentState int

const (
	Idle AgentState = iota
	ReceivingManifest
	ReceivingAlgorithm
	ReceivingData
	Running
	ConsumingResults
	Complete
	Failed
)

//go:generate stringer -type=AgentEvent
type AgentEvent int

const (
	Start AgentEvent = iota
	ManifestReceived
	AlgorithmReceived
	DataReceived
	RunComplete
	ResultsConsumed
	RunFailed
)

//go:generate stringer -type=Status
type Status uint8

const (
	IdleState Status = iota
	InProgress
	Ready
	Completed
	Terminated
	Warning
)

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
	mu              sync.Mutex
	computation     Computation               // Holds the current computation request details.
	algorithm       algorithm.Algorithm       // Filepath to the algorithm received for the computation.
	result          []byte                    // Stores the result of the computation.
	sm              statemachine.StateMachine // Manages the state transitions of the agent service.
	runError        error                     // Stores any error encountered during the computation run.
	eventSvc        events.Service            // Service for publishing events related to computation.
	quoteProvider   client.QuoteProvider      // Provider for generating attestation quotes.
	logger          *slog.Logger              // Logger for the agent service.
	resultsConsumed bool                      // Indicates if the results have been consumed.
}

var _ Service = (*agentService)(nil)

// New instantiates the agent service implementation.
func New(ctx context.Context, logger *slog.Logger, eventSvc events.Service, cmp Computation, quoteProvider client.QuoteProvider) Service {
	sm := statemachine.NewStateMachine(Idle)
	svc := &agentService{
		sm:            sm,
		eventSvc:      eventSvc,
		quoteProvider: quoteProvider,
		logger:        logger,
		computation:   cmp,
	}

	transitions := []statemachine.Transition{
		{From: Idle, Event: Start, To: ReceivingManifest},
		{From: ReceivingManifest, Event: ManifestReceived, To: ReceivingAlgorithm},
	}

	if len(cmp.Datasets) == 0 {
		transitions = append(transitions, statemachine.Transition{From: ReceivingAlgorithm, Event: AlgorithmReceived, To: Running})
	} else {
		transitions = append(transitions, statemachine.Transition{From: ReceivingAlgorithm, Event: AlgorithmReceived, To: ReceivingData})
		transitions = append(transitions, statemachine.Transition{From: ReceivingData, Event: DataReceived, To: Running})
	}

	transitions = append(transitions, []statemachine.Transition{
		{From: Running, Event: RunComplete, To: ConsumingResults},
		{From: Running, Event: RunFailed, To: Failed},
		{From: ConsumingResults, Event: ResultsConsumed, To: Complete},
	}...)

	for _, t := range transitions {
		sm.AddTransition(t)
	}

	sm.SetAction(Idle, svc.publishEvent(IdleState.String()))
	sm.SetAction(ReceivingManifest, svc.publishEvent(InProgress.String()))
	sm.SetAction(ReceivingAlgorithm, svc.publishEvent(InProgress.String()))
	sm.SetAction(ReceivingData, svc.publishEvent(InProgress.String()))
	sm.SetAction(Running, svc.runComputation)
	sm.SetAction(ConsumingResults, svc.publishEvent(Ready.String()))
	sm.SetAction(Complete, svc.publishEvent(Completed.String()))
	sm.SetAction(Failed, svc.publishEvent(Failed.String()))

	go func() {
		if err := sm.Start(ctx); err != nil {
			logger.Error(err.Error())
		}
	}()
	sm.SendEvent(Start)
	defer sm.SendEvent(ManifestReceived)

	return svc
}

func (as *agentService) Algo(ctx context.Context, algo Algorithm) error {
	as.mu.Lock()
	defer as.mu.Unlock()
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
		as.algorithm = binary.NewAlgorithm(as.logger, as.eventSvc, f.Name(), args)
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
		as.algorithm = python.NewAlgorithm(as.logger, as.eventSvc, runtime, requirementsFile, f.Name(), args)
	case string(algorithm.AlgoTypeWasm):
		as.algorithm = wasm.NewAlgorithm(as.logger, as.eventSvc, f.Name(), args)
	case string(algorithm.AlgoTypeDocker):
		as.algorithm = docker.NewAlgorithm(as.logger, as.eventSvc, f.Name())
	}

	if err := os.Mkdir(algorithm.DatasetsDir, 0o755); err != nil {
		return fmt.Errorf("error creating datasets directory: %v", err)
	}

	if as.algorithm != nil {
		as.sm.SendEvent(AlgorithmReceived)
	}

	return nil
}

func (as *agentService) Data(ctx context.Context, dataset Dataset) error {
	as.mu.Lock()
	defer as.mu.Unlock()
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
		defer as.sm.SendEvent(DataReceived)
	}

	return nil
}

func (as *agentService) Result(ctx context.Context) ([]byte, error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	currentState := as.sm.GetState()
	if currentState != ConsumingResults && currentState != Complete && currentState != Failed {
		return []byte{}, ErrResultsNotReady
	}

	index, ok := IndexFromContext(ctx)
	if !ok {
		return []byte{}, ErrUndeclaredConsumer
	}

	if index < 0 || index >= len(as.computation.ResultConsumers) {
		return []byte{}, ErrUndeclaredConsumer
	}

	if !as.resultsConsumed && currentState == ConsumingResults {
		as.resultsConsumed = true
		defer as.sm.SendEvent(ResultsConsumed)
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

func (as *agentService) runComputation(state statemachine.State) {
	as.publishEvent(InProgress.String())(state)
	as.logger.Debug("computation run started")
	defer func() {
		if as.runError != nil {
			as.sm.SendEvent(RunFailed)
		} else {
			as.sm.SendEvent(RunComplete)
		}
	}()

	if err := os.Mkdir(algorithm.ResultsDir, 0o755); err != nil {
		as.runError = fmt.Errorf("error creating results directory: %s", err.Error())
		as.logger.Warn(as.runError.Error())
		as.publishEvent(Failed.String())(state)
		return
	}

	defer func() {
		if err := os.RemoveAll(algorithm.ResultsDir); err != nil {
			as.logger.Warn(fmt.Sprintf("error removing results directory and its contents: %s", err.Error()))
		}
		if err := os.RemoveAll(algorithm.DatasetsDir); err != nil {
			as.logger.Warn(fmt.Sprintf("error removing datasets directory and its contents: %s", err.Error()))
		}
	}()

	as.publishEvent(InProgress.String())(state)
	if err := as.algorithm.Run(); err != nil {
		as.runError = err
		as.logger.Warn(fmt.Sprintf("failed to run computation: %s", err.Error()))
		as.publishEvent(Failed.String())(state)
		return
	}

	results, err := internal.ZipDirectoryToMemory(algorithm.ResultsDir)
	if err != nil {
		as.runError = err
		as.logger.Warn(fmt.Sprintf("failed to zip results: %s", err.Error()))
		as.publishEvent(Failed.String())(state)
		return
	}

	as.publishEvent(Completed.String())(state)

	as.result = results
}

func (as *agentService) publishEvent(status string) statemachine.Action {
	return func(state statemachine.State) {
		if err := as.eventSvc.SendEvent(state.String(), status, json.RawMessage{}); err != nil {
			as.logger.Warn(err.Error())
		}
	}
}
