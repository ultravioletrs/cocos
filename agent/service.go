// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"

	"github.com/ultravioletrs/cocos-ai/pkg/socket"
)

var _ Service = (*agentService)(nil)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")
	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
	// errUndeclaredAlgorithm indicates algorithm was not declared in computation manifest.
	errUndeclaredAlgorithm = errors.New("algorithm not declared in computation manifest")
	// errUndeclaredAlgorithm indicates algorithm was not declared in computation manifest.
	errUndeclaredDataset = errors.New("dataset not declared in computation manifest")
	// errProviderMissmatch algorithm/dataset provider does not match computation manifest.
	errProviderMissmatch = errors.New("provider does not match declaration on manifest")
	// errAllManifestItemsReceived indicates no new computation manifest items expected.
	errAllManifestItemsReceived = errors.New("all expected manifest Items have been received")
	// errUndeclaredConsumer indicates the consumer requesting results in not declared in computation manifest.
	errUndeclaredConsumer = errors.New("result consumer is undeclared in computation manifest")
)

type Metadata map[string]interface{}

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	Run(ctx context.Context, cmp Computation) (string, error)
	Algo(ctx context.Context, algorithm Algorithm) (string, error)
	Data(ctx context.Context, dataset Dataset) (string, error)
	Result(ctx context.Context, consumer string) ([]byte, error)
	Attestation(ctx context.Context) ([]byte, error)
}

type agentService struct {
	computation Computation
	algorithms  [][]byte
	datasets    [][]byte
	result      []byte
	attestation []byte
}

const (
	socketPath = "unix_socket"
	pyRuntime  = "python3"
)

var _ Service = (*agentService)(nil)

// New instantiates the agent service implementation.
func New() Service {
	return &agentService{}
}

func (as *agentService) Run(ctx context.Context, cmp Computation) (string, error) {
	cmpJSON, err := json.Marshal(cmp)
	if err != nil {
		return "", err
	}

	as.computation = cmp

	// Calculate the SHA-256 hash of the algorithm
	hash := sha256.Sum256(cmpJSON)
	cmpHash := hex.EncodeToString(hash[:])

	return cmpHash, nil // return computation hash.
}

func (as *agentService) Algo(ctx context.Context, algorithm Algorithm) (string, error) {
	if len(as.computation.Algorithms) == 0 {
		return "", errAllManifestItemsReceived
	}
	index := containsID(as.computation.Algorithms, algorithm.ID)
	switch index {
	case -1:
		return "", errUndeclaredAlgorithm
	default:
		if as.computation.Algorithms[index].Provider != algorithm.Provider {
			return "", errProviderMissmatch
		}
		as.computation.Algorithms = slices.Delete(as.computation.Algorithms, index, index+1)
	}

	as.algorithms = append(as.algorithms, algorithm.Algorithm)

	// Calculate the SHA-256 hash of the algorithm.
	hash := sha256.Sum256(algorithm.Algorithm)
	algorithmHash := hex.EncodeToString(hash[:])

	// Return the algorithm hash or an error.
	return algorithmHash, nil
}

func (as *agentService) Data(ctx context.Context, dataset Dataset) (string, error) {
	if len(as.computation.Datasets) == 0 {
		return "", errAllManifestItemsReceived
	}
	index := containsID(as.computation.Datasets, dataset.ID)
	switch index {
	case -1:
		return "", errUndeclaredDataset
	default:
		if as.computation.Datasets[index].Provider != dataset.Provider {
			return "", errProviderMissmatch
		}
		as.computation.Datasets = slices.Delete(as.computation.Datasets, index, index+1)
	}

	as.datasets = append(as.datasets, dataset.Dataset)

	// Calculate the SHA-256 hash of the dataset.
	hash := sha256.Sum256(dataset.Dataset)
	datasetHash := hex.EncodeToString(hash[:])

	// Return the dataset hash or an error.
	return datasetHash, nil
}

func (as *agentService) Result(ctx context.Context, consumer string) ([]byte, error) {
	if len(as.computation.ResultConsumers) == 0 {
		return []byte{}, errAllManifestItemsReceived
	}
	index := slices.Index(as.computation.ResultConsumers, consumer)
	switch index {
	case -1:
		return []byte{}, errUndeclaredConsumer
	default:
		as.computation.ResultConsumers = slices.Delete(as.computation.ResultConsumers, index, index+1)
	}

	result, err := run(as.algorithms[0], as.datasets[0])
	if err != nil {
		return nil, fmt.Errorf("error performing computation: %v", err)
	}
	as.result = result

	// Return the result file or an error
	return as.result, nil
}

func (as *agentService) Attestation(ctx context.Context) ([]byte, error) {
	// Implement the logic for the Attestation method here
	// Use the provided ctx parameter as needed
	var attestation []byte

	as.attestation = attestation

	return as.attestation, nil
}

func run(algoContent []byte, dataContent []byte) ([]byte, error) {
	listener, err := socket.StartUnixSocketServer(socketPath)
	if err != nil {
		return nil, fmt.Errorf("error creating stdout pipe: %v", err)
	}
	defer listener.Close()

	// Create channels for received data and errors
	dataChannel := make(chan []byte)
	errorChannel := make(chan error)
	go socket.AcceptConnection(listener, dataChannel, errorChannel)

	// Construct the Python script content with CSV data as a command-line argument
	script := string(algoContent)
	data := string(dataContent)
	cmd := exec.Command(pyRuntime, "-c", script, data, socketPath)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting Python script: %v", err)
	}

	var result []byte
	select {
	case result = <-dataChannel:
	case err = <-errorChannel:
		return nil, fmt.Errorf("error receiving data: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("python script execution error: %v", err)
	}

	return result, nil
}
