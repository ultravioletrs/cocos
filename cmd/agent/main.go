package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mainflux/mainflux/logger"
	agent "github.com/ultravioletrs/agent/agent"
	"github.com/ultravioletrs/agent/agent/api"
	agentgrpc "github.com/ultravioletrs/agent/agent/api/grpc"
	agenthttpapi "github.com/ultravioletrs/agent/agent/api/http"
	"github.com/ultravioletrs/agent/internal/env"
	"google.golang.org/grpc"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	opentracing "github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	jconfig "github.com/uber/jaeger-client-go/config"
)

const svcName = "agent"

type config struct {
	LogLevel   string `env:"AGENT_LOG_LEVEL"   envDefault:"info"`
	HTTPPort   string `env:"AGENT_HTTP_PORT"   envDefault:"9031"`
	ServerCert string `env:"AGENT_SERVER_CERT" envDefault:""`
	ServerKey  string `env:"AGENT_SERVER_KEY"  envDefault:""`
	Secret     string `env:"AGENT_SECRET"      envDefault:"secret"`
	GRPCAddr   string `env:"AGENT_GRPC_ADDR"   envDefault:"localhost:7002"`
	JaegerURL  string `env:"AGENT_JAEGER_URL"  envDefault:""`
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := logger.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	agentTracer, agentCloser := initJaeger("agent", cfg.JaegerURL, logger)
	defer agentCloser.Close()

	svc := newService(cfg.Secret, logger)
	errs := make(chan error, 2)

	go startgRPCServer(cfg, &svc, logger, errs)
	go startHTTPServer(agenthttpapi.MakeHandler(agentTracer, svc), cfg.HTTPPort, cfg, logger, errs)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Agent service terminated: %s", err))
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

func newService(secret string, logger logger.Logger) agent.Service {
	svc := agent.New(secret)

	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "agent",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "agent",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	return svc
}

func startHTTPServer(handler http.Handler, port string, cfg config, logger logger.Logger, errs chan error) {
	p := fmt.Sprintf(":%s", port)
	if cfg.ServerCert != "" || cfg.ServerKey != "" {
		logger.Info(fmt.Sprintf("Agent service started using https on port %s with cert %s key %s",
			port, cfg.ServerCert, cfg.ServerKey))
		errs <- http.ListenAndServeTLS(p, cfg.ServerCert, cfg.ServerKey, handler)
		return
	}
	logger.Info(fmt.Sprintf("Agent service started using http on port %s", cfg.HTTPPort))
	errs <- http.ListenAndServe(p, handler)
}

func startgRPCServer(cfg config, svc *agent.Service, logger logger.Logger, errs chan error) {
	// Create a gRPC server object
	tracer := opentracing.GlobalTracer()
	server := grpc.NewServer()
	// Register the implementation of the service with the server
	agent.RegisterAgentServiceServer(server, agentgrpc.NewServer(tracer, *svc))
	// Listen to a port and serve incoming requests
	listener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf(err.Error())
	}
	logger.Info(fmt.Sprintf("Agent service started using gRPC on address %s", cfg.GRPCAddr))
	errs <- server.Serve(listener)
}
