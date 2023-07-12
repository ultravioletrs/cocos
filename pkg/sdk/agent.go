package sdk

import (
	"context"
	"log"

	"google.golang.org/grpc"

	"time"

	pb "github.com/ultravioletrs/agent/agent"
)

type Computation struct {
	ID                 string    `json:"id,omitempty" db:"id"`
	Name               string    `json:"name,omitempty" db:"name"`
	Description        string    `json:"description,omitempty" db:"description"`
	Status             string    `json:"status,omitempty" db:"status"`
	Owner              string    `json:"owner,omitempty" db:"owner"`
	StartTime          time.Time `json:"start_time,omitempty" db:"start_time"`
	EndTime            time.Time `json:"end_time,omitempty" db:"end_time"`
	Datasets           []string  `json:"datasets,omitempty" db:"datasets"`
	Algorithms         []string  `json:"algorithms,omitempty" db:"algorithms"`
	DatasetProviders   []string  `json:"dataset_providers,omitempty" db:"dataset_providers"`
	AlgorithmProviders []string  `json:"algorithm_providers,omitempty" db:"algorithm_providers"`
	ResultConsumers    []string  `json:"result_consumers,omitempty" db:"result_consumers"`
	Ttl                int       `json:"ttl,omitempty" db:"ttl"`
	Metadata           Metadata  `json:"metadata,omitempty" db:"metadata"`
}

type agentSDK struct {
	client pb.AgentServiceClient
	conn   *grpc.ClientConn
}

func NewAgentSDK(conf Config) (SDK, error) {
	conn, err := grpc.Dial(conf.AgentURL, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to the server: %v", err)
		return nil, err
	}

	client := pb.NewAgentServiceClient(conn)

	return &agentSDK{
		client: client,
		conn:   conn,
	}, nil
}

func (sdk *agentSDK) Run(computation Computation) (string, error) {
	request := &pb.RunRequest{
		Computation: []byte("..."),
	}

	response, err := sdk.client.Run(context.Background(), request)
	if err != nil {
		log.Fatalf("Failed to call Run RPC: %v", err)
		return "", err
	}

	return response.Computation, nil
}

func (sdk *agentSDK) UploadAlgorithm(algorithm []byte) (string, error) {
	request := &pb.AlgoRequest{
		Algorithm: algorithm,
	}

	response, err := sdk.client.Algo(context.Background(), request)
	if err != nil {
		log.Fatalf("Failed to call Algo RPC: %v", err)
		return "", err
	}

	return response.AlgorithmID, nil
}

func (sdk *agentSDK) UploadDataset(dataset string) (string, error) {
	request := &pb.DataRequest{
		Dataset: dataset,
	}

	response, err := sdk.client.Data(context.Background(), request)
	if err != nil {
		log.Fatalf("Failed to call Data RPC: %v", err)
		return "", err
	}

	return response.DatasetID, nil
}

func (sdk *agentSDK) Result() ([]byte, error) {
	request := &pb.ResultRequest{}

	response, err := sdk.client.Result(context.Background(), request)
	if err != nil {
		log.Fatalf("Failed to call Result RPC: %v", err)
		return nil, err
	}

	return response.File, nil
}

func (sdk *agentSDK) Close() {
	sdk.conn.Close()
}
