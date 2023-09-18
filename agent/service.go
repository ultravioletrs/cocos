// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
)

var (
	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
)

type Metadata map[string]interface{}

// Service specifies an API that must be fullfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	Run(ctx context.Context, cmp Computation) (string, error)
	Algo(ctx context.Context, algorithm []byte) (string, error)
	Data(ctx context.Context, dataset []byte) (string, error)
	Result(ctx context.Context) ([]byte, error)
}

type agentService struct {
	computation Computation
	algorithms  [][]byte
	datasets    [][]byte
	result      []byte
}

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

	return string(cmpJSON), nil // return the JSON string as the function's string return value
}

func (as *agentService) Algo(ctx context.Context, algorithm []byte) (string, error) {
	// Implement the logic for the Algo method based on your requirements
	// Use the provided ctx and algorithm parameters as needed

	as.algorithms = append(as.algorithms, algorithm)

	// Perform some processing on the algorithm byte array
	// For example, generate a unique ID for the algorithm
	algorithmID := "algo123"

	// Return the algorithm ID or an error
	return algorithmID, nil
}

func (as *agentService) Data(ctx context.Context, dataset []byte) (string, error) {
	// Implement the logic for the Data method based on your requirements
	// Use the provided ctx and dataset parameters as needed

	as.datasets = append(as.datasets, dataset)

	// Perform some processing on the dataset string
	// For example, generate a unique ID for the dataset
	datasetID := "dataset456"

	// Return the dataset ID or an error
	return datasetID, nil
}

func (as *agentService) Result(ctx context.Context) ([]byte, error) {
	// Implement the logic for the Result method based on your requirements
	// Use the provided ctx parameter as needed

	// Perform some processing to retrieve the computation result file
	// For example, read the file from storage or generate a dummy result
	result, err := run(as.algorithms[0], as.datasets[0])
	if err != nil {
		return nil, fmt.Errorf("error performing computation: %v", err)
	}
	as.result = result

	// Return the result file or an error
	return as.result, nil
}

func run(algoContent []byte, dataContent []byte) ([]byte, error) {
	// Construct the Python script content with CSV data as a command-line argument
	script := string(algoContent)
	data := string(dataContent)
	socketPath := "unix_socket"

	listener, err := startUnixSocketServer(socketPath)
	if err != nil {
		return nil, fmt.Errorf("error creating stdout pipe: %v", err)
	}
	defer listener.Close()

	// Create channels for received data and errors
	dataChannel := make(chan []byte)
	errorChannel := make(chan error)
	go acceptConnections(listener, dataChannel, errorChannel)

	// Run the Python script with the script and data as input
	cmd := exec.Command("python3", "-c", script, data, socketPath)

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting Python script: %v", err)
	}

	var receivedData []byte
	// Process received data or errors
	select {
	case receivedData = <-dataChannel:
	case err = <-errorChannel:
		return nil, fmt.Errorf("error receiving data: %v", err)
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("python script execution error: %v", err)
	}

	fmt.Println("Python script execution completed.")

	return receivedData, nil
}

func startUnixSocketServer(socketPath string) (net.Listener, error) {
	// Remove any existing socket file
	_ = os.Remove(socketPath)

	// Create a Unix domain socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("error creating socket listener: %v", err)
	}

	fmt.Println("Unix domain socket server is listening on", socketPath)

	return listener, nil
}

func acceptConnections(listener net.Listener, dataChannel chan []byte, errorChannel chan error) {
	conn, err := listener.Accept()
	if err != nil {
		errorChannel <- fmt.Errorf("error accepting connection:: %v", err)
	}

	// Handle the connection in a goroutine and send the received data or error to channels
	handleConnection(conn, dataChannel, errorChannel)
}

func handleConnection(conn net.Conn, dataChannel chan []byte, errorChannel chan error) {
	defer conn.Close()

	// Create a dynamic buffer to store incoming data
	var buffer []byte
	tmp := make([]byte, 1024) // Temporary buffer for reading data

	for {
		// Read data into the temporary buffer
		n, err := conn.Read(tmp)
		if err != nil {
			if err == io.EOF {
				// End of data, break the loop
				break
			}
			errorChannel <- err // Send the error to the error channel
		}

		// Append the read data to the dynamic buffer
		buffer = append(buffer, tmp[:n]...)
	}

	// Send the received data to the data channel
	dataChannel <- buffer
}
