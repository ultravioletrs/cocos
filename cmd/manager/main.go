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
	"github.com/ultravioletrs/manager/manager"
	"github.com/ultravioletrs/manager/manager/api"
	managergrpc "github.com/ultravioletrs/manager/manager/api/manager/grpc"
	managerhttpapi "github.com/ultravioletrs/manager/manager/api/manager/http"
	"google.golang.org/grpc"

	"github.com/digitalocean/go-libvirt"
)

const (
	defLogLevel     = "error"
	defHTTPPort     = "9021"
	defJaegerURL    = ""
	defServerCert   = ""
	defServerKey    = ""
	defSecret       = "secret"
	defGRPCAddr     = "localhost:7001"
	defAgentURL     = "localhost:7002"
	defAgentTimeout = "1s"

	envLogLevel     = "CC_MANAGER_LOG_LEVEL"
	envHTTPPort     = "CC_MANAGER_HTTP_PORT"
	envServerCert   = "CC_MANAGER_SERVER_CERT"
	envServerKey    = "CC_MANAGER_SERVER_KEY"
	envSecret       = "CC_MANAGER_SECRET"
	envJaegerURL    = "CC_JAEGER_URL"
	envGRPCAddr     = "CC_MANAGER_GRPC_PORT"
	envAgentURL     = "COCOS_COMPUTATIONS_AGENT_GRPC_URL"
	envAgentTimeout = "COCOS_COMPUTATIONS_AGENT_GRPC_TIMEOUT"
)

type config struct {
	logLevel     string
	httpPort     string
	authHTTPPort string
	authGRPCPort string
	serverCert   string
	serverKey    string
	secret       string
	jaegerURL    string
	GRPCAddr     string
	agentURL     string
	agentTimeout time.Duration
}

func main() {
	cfg := loadConfig()

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	managerTracer, managerCloser := initJaeger("manager", cfg.jaegerURL, logger)
	defer managerCloser.Close()

	libvirtConn := initLibvirt(logger)
	defer libvirtConn.Disconnect()

	idProvider := uuid.New()

	conn := connectToGrpc("agent", cfg.agentURL, logger)
	agent := agent.NewAgentServiceClient(conn)

	svc := newService(cfg.secret, libvirtConn, idProvider, agent, logger)

	errs := make(chan error, 2)
	go startgRPCServer(cfg, &svc, logger, errs)
	go startHTTPServer(managerhttpapi.MakeHandler(managerTracer, svc), cfg.httpPort, cfg, logger, errs)

	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("Manager service terminated: %s", err))

}

func loadConfig() config {
	agentTimeout, err := time.ParseDuration(mainflux.Env(envAgentTimeout, defAgentTimeout))
	if err != nil {
		log.Fatalf("Invalid %s value: %s", agentTimeout, err.Error())
	}

	return config{
		agentTimeout: agentTimeout,
		logLevel:     mainflux.Env(envLogLevel, defLogLevel),
		httpPort:     mainflux.Env(envHTTPPort, defHTTPPort),
		serverCert:   mainflux.Env(envServerCert, defServerCert),
		serverKey:    mainflux.Env(envServerKey, defServerKey),
		jaegerURL:    mainflux.Env(envJaegerURL, defJaegerURL),
		secret:       mainflux.Env(envSecret, defSecret),
		GRPCAddr:     mainflux.Env(envGRPCAddr, defGRPCAddr),
		agentURL:     mainflux.Env(envAgentURL, defAgentURL),
	}
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
	if cfg.serverCert != "" || cfg.serverKey != "" {
		logger.Info(fmt.Sprintf("Manager service started using https on port %s with cert %s key %s",
			port, cfg.serverCert, cfg.serverKey))
		errs <- http.ListenAndServeTLS(p, cfg.serverCert, cfg.serverKey, handler)
		return
	}
	logger.Info(fmt.Sprintf("Manager service started using http on port %s", cfg.httpPort))
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
		logger.Error(fmt.Sprintf("Failed to connect to things service: %s", err))
		os.Exit(1)
	}
	logger.Info(fmt.Sprintf("connected to %s gRPC server on %s", name, url))

	return conn
}
