//
// Copyright (c) 2019
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

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
	"time"

	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/uuid"
	opentracing "github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	jconfig "github.com/uber/jaeger-client-go/config"
	"github.com/ultravioletrs/agent/agent"
	agentgrpc "github.com/ultravioletrs/agent/agent/api/grpc"
	"github.com/ultravioletrs/manager/internal/env"
	"github.com/ultravioletrs/manager/manager"
	"github.com/ultravioletrs/manager/manager/api"
	managergrpc "github.com/ultravioletrs/manager/manager/api/grpc"
	managerhttpapi "github.com/ultravioletrs/manager/manager/api/http"
	"google.golang.org/grpc"

	"github.com/digitalocean/go-libvirt"
)

const svcName = "manager"

type config struct {
	LogLevel     string `env:"MANAGER_LOG_LEVEL"   envDefault:"info"`
	HTTPPort     string `env:"MANAGER_HTTP_PORT"   envDefault:"9021"`
	ServerCert   string `env:"MANAGER_SERVER_CERT" envDefault:""`
	ServerKey    string `env:"MANAGER_SERVER_KEY"  envDefault:""`
	Secret       string `env:"MANAGER_SECRET"      envDefault:"secret"`
	GRPCAddr     string `env:"MANAGER_GRPC_ADDR"   envDefault:"localhost:7001"`
	AgentGRPCURL string `env:"AGENT_GRPC_URL"      envDefault:"localhost:7002"`
	AgentTimeout string `env:"AGENT_GRPC_TIMEOUT"  envDefault:"1s"`
	JaegerURL    string `env:"MANAGER_JAEGER_URL"  envDefault:""`
	InstanceID   string `env:"MANAGER_INSTANCE_ID" envDefault:""`
}

func main() {
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := logger.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if cfg.InstanceID == "" {
		cfg.InstanceID, err = uuid.New().ID()
		if err != nil {
			logger.Fatal(fmt.Sprintf("Failed to generate instance ID: %s", err))
		}
	}

	managerTracer, managerCloser := initJaeger("manager", cfg.JaegerURL, logger)
	defer managerCloser.Close()

	libvirtConn := initLibvirt(logger)
	defer func() {
		if err := libvirtConn.Disconnect(); err != nil {
			logger.Error(fmt.Sprintf("Error disconnecting from libvirt: %s", err))
		}
	}()

	idProvider := uuid.New()

	agentTracer, agentCloser := initJaeger("agent", cfg.JaegerURL, logger)
	defer agentCloser.Close()
	conn := connectToGrpc("agent", cfg.AgentGRPCURL, logger)

	timeout, err := time.ParseDuration(cfg.AgentTimeout)
	if err != nil {
		log.Fatalf("failed to parse agent timeout: %s", err)
	}
	agent := agentgrpc.NewClient(agentTracer, conn, timeout)

	svc := newService(cfg.Secret, libvirtConn, idProvider, agent, logger)

	errs := make(chan error, 2)
	go startgRPCServer(cfg, &svc, logger, errs)
	go startHTTPServer(managerhttpapi.MakeHandler(managerTracer, svc, cfg.InstanceID), cfg.HTTPPort, cfg, logger, errs)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Manager service terminated: %s", err))
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

func newService(secret string, libvirtConn *libvirt.Libvirt, idp mainflux.IDProvider, agent agent.AgentServiceClient, logger logger.Logger) manager.Service {
	svc := manager.New(secret, libvirtConn, idp, agent)

	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "manager",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "manager",
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
		logger.Info(fmt.Sprintf("Manager service started using https on port %s with cert %s key %s",
			port, cfg.ServerCert, cfg.ServerKey))
		errs <- http.ListenAndServeTLS(p, cfg.ServerCert, cfg.ServerKey, handler)
		return
	}
	logger.Info(fmt.Sprintf("Manager service started using http on port %s", cfg.HTTPPort))
	errs <- http.ListenAndServe(p, handler)
}

func startgRPCServer(cfg config, svc *manager.Service, logger logger.Logger, errs chan error) {
	// Create a gRPC server object
	tracer := opentracing.GlobalTracer()
	server := grpc.NewServer()
	// Register the implementation of the service with the server
	manager.RegisterManagerServiceServer(server, managergrpc.NewServer(tracer, *svc))
	// Listen to a port and serve incoming requests
	listener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatalf(err.Error())
	}
	logger.Info(fmt.Sprintf("Manager service started using gRPC on address %s", cfg.GRPCAddr))
	errs <- server.Serve(listener)
}

func initLibvirt(logger logger.Logger) *libvirt.Libvirt {
	// This dials libvirt on the local machine, but you can substitute the first
	// two parameters with "tcp", "<ip address>:<port>" to connect to libvirt on
	// a remote machine.
	c, err := net.DialTimeout("unix", "/var/run/libvirt/libvirt-sock", 2*time.Second)
	if err != nil {
		log.Fatalf("failed to dial libvirt: %v", err)
	}

	l := libvirt.New(c)
	if err := l.Connect(); err != nil {
		log.Fatalf("failed to connect: %v", err)
	}

	v, err := l.Version()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to retrieve libvirt version: %v", err))
	}
	fmt.Println("Version:", v)

	domains, err := l.Domains()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to retrieve domains: %v", err))
	}
	fmt.Println("ID\tName\t\tUUID")
	fmt.Printf("--------------------------------------------------------\n")
	for _, d := range domains {
		fmt.Printf("%d\t%s\t%x\n", d.ID, d.Name, d.UUID)
	}

	return l
}

func connectToGrpc(name string, url string, logger logger.Logger) *grpc.ClientConn {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())

	conn, err := grpc.Dial(url, opts...)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to %s service: %s", name, err))
		os.Exit(1)
	}
	logger.Info(fmt.Sprintf("connected to %s gRPC server on %s", name, url))

	return conn
}
