package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	mflog "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/uuid"
	opentracing "github.com/opentracing/opentracing-go"
	jconfig "github.com/uber/jaeger-client-go/config"
	agent "github.com/ultravioletrs/agent/agent"
	"github.com/ultravioletrs/agent/agent/api"
	agentgrpc "github.com/ultravioletrs/agent/agent/api/grpc"
	httpapi "github.com/ultravioletrs/agent/agent/api/http"
	"github.com/ultravioletrs/agent/agent/tracing"
	"github.com/ultravioletrs/agent/internal"
	"github.com/ultravioletrs/agent/internal/env"
	"github.com/ultravioletrs/agent/internal/server"
	grpcserver "github.com/ultravioletrs/agent/internal/server/grpc"
	httpserver "github.com/ultravioletrs/agent/internal/server/http"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "agent"
	envPrefixHTTP  = "AGENT_HTTP_"
	envPrefixGRPC  = "AGENT_GRPC_"
	defSvcHTTPPort = "9031"
	defSvcGRPCPort = "7002"
)

type config struct {
	LogLevel   string `env:"AGENT_LOG_LEVEL"   envDefault:"info"`
	Secret     string `env:"AGENT_SECRET"      envDefault:"secret"`
	JaegerURL  string `env:"AGENT_JAEGER_URL"  envDefault:"localhost:14268/api/traces"`
	InstanceID string `env:"AGENT_INSTANCE_ID" envDefault:""`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := mflog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if cfg.InstanceID == "" {
		cfg.InstanceID, err = uuid.New().ID()
		if err != nil {
			log.Fatalf("Failed to generate instanceID: %s", err)
		}
	}

	agentTracer, agentCloser := initJaeger("agent", cfg.JaegerURL, logger)
	defer agentCloser.Close()

	svc := newService(cfg.Secret, logger, trace.NewNoopTracerProvider().Tracer(svcName))

	var httpServerConfig = server.Config{Port: defSvcHTTPPort}
	if err := env.Parse(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Fatal(fmt.Sprintf("failed to load %s gRPC server configuration : %s", svcName, err))
	}
	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, httpapi.MakeHandler(agentTracer, svc, cfg.InstanceID), logger)

	var grpcServerConfig = server.Config{Port: defSvcGRPCPort}
	if err := env.Parse(&grpcServerConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		log.Fatalf("failed to load %s gRPC server configuration : %s", svcName, err.Error())
	}
	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		agent.RegisterAgentServiceServer(srv, agentgrpc.NewServer(agentTracer, svc))
	}
	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger)

	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return gs.Start()
	})

	g.Go(func() error {
		return server.StopHandler(ctx, cancel, logger, svcName, hs, gs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}
}

func initJaeger(svcName, url string, logger mflog.Logger) (opentracing.Tracer, io.Closer) {
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

func newService(secret string, logger mflog.Logger, tracer trace.Tracer) agent.Service {
	svc := agent.New(secret)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc
}
