package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/mainflux/mainflux/logger"
	"github.com/opentracing/opentracing-go"
	jconfig "github.com/uber/jaeger-client-go/config"
	"github.com/ultravioletrs/agent/agent"
	agentgrpc "github.com/ultravioletrs/agent/agent/api/grpc"
	ggrpc "google.golang.org/grpc"
)

type AgentSDK struct {
	client agent.AgentServiceClient
	logger logger.Logger
}

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

type Metadata map[string]interface{}

func NewAgentSDK(conf Config, log logger.Logger) (*AgentSDK, error) {
	conn := connectToGrpc("agent", conf.AgentURL, log)
	agentTracer, _ := initJaeger("agent", conf.JaegerURL, log)
	agentClient := agentgrpc.NewClient(agentTracer, conn, conf.AgentTimeout)

	return &AgentSDK{
		client: agentClient,
		logger: log,
	}, nil
}

func (sdk *AgentSDK) Run(computation Computation) (string, error) {
	computationBytes, err := json.Marshal(computation)
	if err != nil {
		sdk.logger.Error("Failed to marshal computation")
		return "", err
	}

	request := &agent.RunRequest{
		Computation: computationBytes,
	}
	response, err := sdk.client.Run(context.Background(), request)
	if err != nil {
		sdk.logger.Error("Failed to call Run RPC")
		return "", err
	}

	return response.Computation, nil
}

func (sdk *AgentSDK) UploadAlgorithm(algorithm []byte) (string, error) {
	request := &agent.AlgoRequest{
		Algorithm: algorithm,
	}

	response, err := sdk.client.Algo(context.Background(), request)
	if err != nil {
		sdk.logger.Error("Failed to call Algo RPC")
		return "", err
	}

	return response.AlgorithmID, nil
}

func (sdk *AgentSDK) UploadDataset(dataset string) (string, error) {
	request := &agent.DataRequest{
		Dataset: dataset,
	}

	response, err := sdk.client.Data(context.Background(), request)
	if err != nil {
		sdk.logger.Error("Failed to call Data RPC")
		return "", err
	}

	return response.DatasetID, nil
}

func (sdk *AgentSDK) Result() ([]byte, error) {
	request := &agent.ResultRequest{}
	ctx, _ := context.WithTimeout(context.Background(), time.Second*100)
	fmt.Println("asdhfgdkwehv")
	response, err := sdk.client.Result(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Result RPC")
		return nil, err
	}

	return response.File, nil
}

func connectToGrpc(name string, url string, logger logger.Logger) *ggrpc.ClientConn {
	opts := []ggrpc.DialOption{ggrpc.WithInsecure()}
	conn, err := ggrpc.Dial(url, opts...)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to %s service: %s", name, err))
		os.Exit(1)
	}
	logger.Info(fmt.Sprintf("Connected to %s gRPC server on %s", name, url))

	return conn
}

func initJaeger(svcName, url string, logger logger.Logger) (opentracing.Tracer, io.Closer) {
	if url == "" {
		return opentracing.NoopTracer{}, ioutil.NopCloser(nil)
	}

	tracer, closer, err := jconfig.Configuration{
		ServiceName: svcName,
		Sampler: &jconfig.SamplerConfig{
			Type:  "const",
			Param: 1,
		},
		Reporter: &jconfig.ReporterConfig{
			LocalAgentHostPort: url,
			LogSpans:           true,
		},
	}.NewTracer()
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger client: %s", err))
		os.Exit(1)
	}

	return tracer, closer
}
