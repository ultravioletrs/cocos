package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/mainflux/mainflux/logger"
	"github.com/opentracing/opentracing-go"
	"github.com/spf13/cobra"
	jconfig "github.com/uber/jaeger-client-go/config"
	agentgrpc "github.com/ultravioletrs/agent/agent/api/grpc"
	"github.com/ultravioletrs/agent/cli"
	"github.com/ultravioletrs/agent/internal/env"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
	ggrpc "google.golang.org/grpc"
)

const svcName = "cli"

type config struct {
	LogLevel         string `env:"AGENT_LOG_LEVEL"      envDefault:"info"`
	AgentGRPCURL     string `env:"AGENT_GRPC_URL"       envDefault:"localhost:7002"`
	AgentGRPCTimeout string `env:"AGENT_GRPC_TIMEOUT"   envDefault:"1s"`
	JaegerURL        string `env:"AGENT_JAEGER_URL"     envDefault:""`
}

func main() {
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := logger.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("Error creating logger: %s", err)
	}

	conn := connectToGrpc("agent", cfg.AgentGRPCURL, logger)

	agentTracer, agentCloser := initJaeger("agent", cfg.JaegerURL, logger)
	defer agentCloser.Close()

	timeout, err := time.ParseDuration(cfg.AgentGRPCTimeout)
	if err != nil {
		log.Fatalf("Error parsing timeout: %s", err)
	}
	agentClient := agentgrpc.NewClient(agentTracer, conn, timeout)

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
	rootCmd.AddCommand(cli.NewRunCmd(sdk))

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
