// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	sync "sync"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/binary"
	"github.com/ultravioletrs/cocos/agent/algorithm/docker"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"github.com/ultravioletrs/cocos/agent/algorithm/wasm"
	"github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/agent/statemachine"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
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
	Starting
)

const (
	algoFilePermission = 0o700
)

const (
	ImaMeasurementsFilePath = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
	ImaPcrIndex             = 10
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
	// ErrAttestationVTpmFailed vTPM attestation failed.
	ErrAttestationVTpmFailed = errors.New("failed to get vTPM quote")
	// ErrFetchAzureToken azure token fetch failed.
	ErrFetchAzureToken = errors.New("failed to get azure token")
	// ErrAttType indicates that the attestation type that is requested does not exist or is not supported.
	ErrAttestationType = errors.New("attestation type does not exist or is not supported")
)

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	InitComputation(ctx context.Context, cmp Computation) error
	StopComputation(ctx context.Context) error
	Algo(ctx context.Context, algorithm Algorithm) error
	Data(ctx context.Context, dataset Dataset) error
	Result(ctx context.Context) ([]byte, error)
	Attestation(ctx context.Context, reportData [quoteprovider.Nonce]byte, nonce [vtpm.Nonce]byte, attType attestation.PlatformType) ([]byte, error)
	IMAMeasurements(ctx context.Context) ([]byte, []byte, error)
	AttestationResult(ctx context.Context, nonce [vtpm.Nonce]byte, attType attestation.PlatformType) ([]byte, error)
	State() string
}

type agentService struct {
	mu              sync.Mutex
	computation     Computation               // Holds the current computation request details.
	algorithm       algorithm.Algorithm       // Filepath to the algorithm received for the computation.
	result          []byte                    // Stores the result of the computation.
	sm              statemachine.StateMachine // Manages the state transitions of the agent service.
	runError        error                     // Stores any error encountered during the computation run.
	eventSvc        events.Service            // Service for publishing events related to computation.
	provider        attestation.Provider      // Provider for generating attestation quotes.
	logger          *slog.Logger              // Logger for the agent service.
	resultsConsumed bool                      // Indicates if the results have been consumed.
	cancel          context.CancelFunc        // Cancels the computation context.
	vmpl            int                       // VMPL at which the Agent is running.
}

var _ Service = (*agentService)(nil)

// New instantiates the agent service implementation.
func New(ctx context.Context, logger *slog.Logger, eventSvc events.Service, provider attestation.Provider, vmlp int) Service {
	sm := statemachine.NewStateMachine(Idle)
	ctx, cancel := context.WithCancel(ctx)
	svc := &agentService{
		sm:       sm,
		eventSvc: eventSvc,
		provider: provider,
		logger:   logger,
		cancel:   cancel,
		vmpl:     vmlp,
	}

	transitions := []statemachine.Transition{
		{From: Idle, Event: Start, To: ReceivingManifest},
		{From: ReceivingManifest, Event: ManifestReceived, To: ReceivingAlgorithm},
	}

	transitions = append(transitions, []statemachine.Transition{
		{From: Running, Event: RunComplete, To: ConsumingResults},
		{From: Running, Event: RunFailed, To: Failed},
		{From: ConsumingResults, Event: ResultsConsumed, To: Complete},
	}...)

	for _, t := range transitions {
		sm.AddTransition(t)
	}

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

	time.Sleep(100 * time.Millisecond)
	sm.SendEvent(Start)

	time.Sleep(100 * time.Millisecond)

	return svc
}

func (as *agentService) State() string {
	return as.sm.GetState().String()
}

func (as *agentService) InitComputation(ctx context.Context, cmp Computation) error {
	if as.sm.GetState() != ReceivingManifest {
		return ErrStateNotReady
	}
	defer as.sm.SendEvent(ManifestReceived)

	as.mu.Lock()
	defer as.mu.Unlock()

	as.computation = cmp

	transitions := []statemachine.Transition{}

	if len(cmp.Datasets) == 0 {
		transitions = append(transitions, statemachine.Transition{From: ReceivingAlgorithm, Event: AlgorithmReceived, To: Running})
	} else {
		transitions = append(transitions, statemachine.Transition{From: ReceivingAlgorithm, Event: AlgorithmReceived, To: ReceivingData})
		transitions = append(transitions, statemachine.Transition{From: ReceivingData, Event: DataReceived, To: Running})
	}

	for _, t := range transitions {
		as.sm.AddTransition(t)
	}

	return nil
}

func (as *agentService) StopComputation(ctx context.Context) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.eventSvc.SendEvent(as.computation.ID, "Stopped", "Stopped", json.RawMessage{})

	as.cancel()

	if as.algorithm != nil {
		if err := as.algorithm.Stop(); err != nil {
			return fmt.Errorf("error stopping computation: %v", err)
		}
	}

	if err := os.RemoveAll(algorithm.DatasetsDir); err != nil {
		return fmt.Errorf("error removing datasets directory: %v", err)
	}

	if err := os.RemoveAll(algorithm.ResultsDir); err != nil {
		return fmt.Errorf("error removing results directory: %v", err)
	}

	as.sm.Reset(Idle)

	as.computation = Computation{}
	as.algorithm = nil
	as.result = nil
	as.runError = nil
	as.resultsConsumed = false

	ctx, cancel := context.WithCancel(ctx)
	as.cancel = cancel

	go func() {
		if err := as.sm.Start(ctx); err != nil {
			as.logger.Error(err.Error())
		}
	}()

	time.Sleep(100 * time.Millisecond)
	as.sm.SendEvent(Start)

	time.Sleep(100 * time.Millisecond)

	return nil
}

func (as *agentService) Algo(ctx context.Context, algo Algorithm) error {
	if as.sm.GetState() != ReceivingAlgorithm {
		return ErrStateNotReady
	}
	as.mu.Lock()
	defer as.mu.Unlock()
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
		as.algorithm = binary.NewAlgorithm(as.logger, as.eventSvc, f.Name(), args, as.computation.ID)
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
		as.algorithm = python.NewAlgorithm(as.logger, as.eventSvc, runtime, requirementsFile, f.Name(), args, as.computation.ID)
	case string(algorithm.AlgoTypeWasm):
		as.algorithm = wasm.NewAlgorithm(as.logger, as.eventSvc, args, f.Name(), as.computation.ID)
	case string(algorithm.AlgoTypeDocker):
		as.algorithm = docker.NewAlgorithm(as.logger, as.eventSvc, f.Name(), as.computation.ID)
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
	if as.sm.GetState() != ReceivingData {
		return ErrStateNotReady
	}
	as.mu.Lock()
	defer as.mu.Unlock()
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
	currentState := as.sm.GetState()
	if currentState != ConsumingResults && currentState != Complete && currentState != Failed {
		return []byte{}, ErrResultsNotReady
	}

	index, ok := IndexFromContext(ctx)
	if !ok {
		return []byte{}, ErrUndeclaredConsumer
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	if index < 0 || index >= len(as.computation.ResultConsumers) {
		return []byte{}, ErrUndeclaredConsumer
	}

	if !as.resultsConsumed && currentState == ConsumingResults {
		as.resultsConsumed = true
		defer as.sm.SendEvent(ResultsConsumed)
	}

	return as.result, as.runError
}

func (as *agentService) Attestation(ctx context.Context, reportData [quoteprovider.Nonce]byte, nonce [vtpm.Nonce]byte, attType attestation.PlatformType) ([]byte, error) {
	switch attType {
	case attestation.SNP, attestation.TDX:
		rawQuote, err := as.provider.TeeAttestation(reportData[:])
		if err != nil {
			return []byte{}, errors.Wrap(ErrAttestationFailed, err)
		}
		return rawQuote, nil
	case attestation.VTPM:
		vTPMQuote, err := as.provider.VTpmAttestation(nonce[:])
		if err != nil {
			return []byte{}, errors.Wrap(ErrAttestationVTpmFailed, err)
		}
		return vTPMQuote, nil
	case attestation.SNPvTPM:
		vTPMQuote, err := as.provider.Attestation(reportData[:], nonce[:])
		if err != nil {
			return []byte{}, errors.Wrap(ErrAttestationVTpmFailed, err)
		}
		return vTPMQuote, nil
	default:
		return []byte{}, ErrAttestationType
	}
}

func (as *agentService) AttestationResult(ctx context.Context, nonce [vtpm.Nonce]byte, attType attestation.PlatformType) ([]byte, error) {
	switch attType {
	case attestation.AzureToken:
		token, err := as.provider.AzureAttestationToken(nonce[:])
		if err != nil {
			return []byte{}, err
		}
		return token, nil
	default:
		return []byte{}, ErrAttestationType
	}
}

func (as *agentService) runComputation(state statemachine.State) {
	as.publishEvent(Starting.String())(state)
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
		as.eventSvc.SendEvent(as.computation.ID, state.String(), status, json.RawMessage{})
	}
}

func (as *agentService) IMAMeasurements(ctx context.Context) ([]byte, []byte, error) {
	data, err := os.ReadFile(ImaMeasurementsFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading Linux IMA measurements file: %s", err.Error())
	}

	pcr10, err := vtpm.GetPCRSHA1Value(ImaPcrIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading TPM PCR #10: %s", err.Error())
	}

	return data, pcr10, nil
}
