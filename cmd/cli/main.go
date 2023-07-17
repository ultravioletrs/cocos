package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/opentracing/opentracing-go"
	"github.com/spf13/cobra"
	jconfig "github.com/uber/jaeger-client-go/config"
	agentgrpc "github.com/ultravioletrs/agent/agent/api/grpc"
	"github.com/ultravioletrs/agent/cli"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
	ggrpc "google.golang.org/grpc"
)

const (
	defAgentURL     = "localhost:7002"
	defTimeout      = time.Second
	defJaegerURL    = ""
	defAgentTimeout = "1s"
	defLogLevel     = "error"

	envAgentURL     = "COCOS_AGENT_URL"
	envTimeout      = "COCOS_AGENT_TIMEOUT"
	envJaegerURL    = "JAEGER_URL"
	envAgentTimeout = "MANAGER_AGENT_GRPC_TIMEOUT"
	envLogLevel     = "AGENT_LOG_LEVEL"
)

type config struct {
	jaegerURL    string
	agentURL     string
	agentTimeout time.Duration
	logLevel     string
}

func loadConfig() (config, error) {
	cfg := config{
		agentURL:  mainflux.Env(envAgentURL, defAgentURL),
		jaegerURL: mainflux.Env(envJaegerURL, defJaegerURL),
	}

	agentTimeoutStr := mainflux.Env(envAgentTimeout, defAgentTimeout)
	agentTimeout, err := time.ParseDuration(agentTimeoutStr)
	if err != nil {
		return config{}, err
	}

	cfg.agentTimeout = agentTimeout
	return cfg, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	conn := connectToGrpc("agent", cfg.agentURL, logger)

	agentTracer, agentCloser := initJaeger("agent", cfg.jaegerURL, logger)
	defer agentCloser.Close()

	agentClient := agentgrpc.NewClient(agentTracer, conn, cfg.agentTimeout)

	sdk := agentsdk.NewAgentSDK(logger, agentClient)

	cli.SetSDK(sdk)

	rootCmd := &cobra.Command{
		Use:   "cli-app",
		Short: "CLI application for Computation Service API",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	rootCmd.AddCommand(cli.NewAlgorithmsCmd(sdk))
	rootCmd.AddCommand(cli.NewDatasetsCmd(sdk))
	rootCmd.AddCommand(cli.NewResultsCmd(sdk))

	if err := rootCmd.Execute(); err != nil {
		logger.Error(fmt.Sprintf("Command execution failed: %s", err))
		os.Exit(1)
	}
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
