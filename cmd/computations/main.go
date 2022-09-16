package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/opentracing/opentracing-go"
	jconfig "github.com/uber/jaeger-client-go/config"
	"github.com/ultravioletrs/clients"
	authapi "github.com/ultravioletrs/clients/api/grpc"
	"github.com/ultravioletrs/cocos/computations"
	"github.com/ultravioletrs/cocos/computations/api/api"
	"github.com/ultravioletrs/cocos/computations/postgres"
	"github.com/ultravioletrs/cocos/internal/db"
	"github.com/ultravioletrs/cocos/internal/env"
	"github.com/ultravioletrs/cocos/internal/errors"
	"github.com/ultravioletrs/cocos/internal/http"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	defLogLevel      = "debug"
	defDBHost        = "localhost"
	defDBPort        = "5432"
	defDBUser        = "cocos"
	defDBPass        = "cocos"
	defDB            = "computations"
	defDBSSLMode     = "disable"
	defDBSSLCert     = ""
	defDBSSLKey      = ""
	defDBSSLRootCert = ""
	defHTTPPort      = "9000"
	defServerCert    = ""
	defServerKey     = ""

	defJaegerURL   = ""
	defAuthTLS     = "false"
	defAuthCACerts = ""
	defAuthURL     = "localhost:8181"
	defAuthTimeout = "1s"

	envLogLevel      = "COCOS_COMPUTATIONS_LOG_LEVEL"
	envDBHost        = "COCOS_COMPUTATIONS_DB_HOST"
	envDBPort        = "COCOS_COMPUTATIONS_DB_PORT"
	envDBUser        = "COCOS_COMPUTATIONS_DB_USER"
	envDBPass        = "COCOS_COMPUTATIONS_DB_PASS"
	envDB            = "COCOS_COMPUTATIONS_DB"
	envDBSSLMode     = "COCOS_COMPUTATIONS_DB_SSL_MODE"
	envDBSSLCert     = "COCOS_COMPUTATIONS_DB_SSL_CERT"
	envDBSSLKey      = "COCOS_COMPUTATIONS_DB_SSL_KEY"
	envDBSSLRootCert = "COCOS_COMPUTATIONS_DB_SSL_ROOT_CERT"
	envHTTPPort      = "COCOS_COMPUTATIONS_HTTP_PORT"
	envServerCert    = "COCOS_COMPUTATIONS_SERVER_CERT"
	envServerKey     = "COCOS_COMPUTATIONS_SERVER_KEY"

	envJaegerURL   = "MF_JAEGER_URL"
	envAuthTLS     = "COCOS_COMPUTATIONS_AUTH_CLIENT_TLS"
	envAuthCACerts = "COCOS_COMPUTATIONS_AUTH_CA_CERTS"
	envAuthURL     = "COCOS_COMPUTATIONS_AUTH_GRPC_URL"
	envAuthTimeout = "COCOS_COMPUTATIONS_AUTH_GRPC_TIMEOUT"
)

const svcName = "Computations"

type config struct {
	logLevel    string
	dbConfig    db.Config
	httpPort    string
	serverCert  string
	serverKey   string
	jaegerURL   string
	authTLS     bool
	authCACerts string
	authURL     string
	authTimeout time.Duration
}

func loadConfig() config {
	authTimeout, err := time.ParseDuration(mainflux.Env(envAuthTimeout, defAuthTimeout))
	if err != nil {
		log.Fatalf("Invalid %s value: %s", envAuthTimeout, err.Error())
	}

	tls, err := strconv.ParseBool(mainflux.Env(envAuthTLS, defAuthTLS))
	if err != nil {
		log.Fatalf("Invalid value passed for %s\n", envAuthTLS)
	}

	dbConfig := db.Config{
		Host:        env.Load(envDBHost, defDBHost),
		Port:        env.Load(envDBPort, defDBPort),
		User:        env.Load(envDBUser, defDBUser),
		Pass:        env.Load(envDBPass, defDBPass),
		Name:        env.Load(envDB, defDB),
		SSLMode:     env.Load(envDBSSLMode, defDBSSLMode),
		SSLCert:     env.Load(envDBSSLCert, defDBSSLCert),
		SSLKey:      env.Load(envDBSSLKey, defDBSSLKey),
		SSLRootCert: env.Load(envDBSSLRootCert, defDBSSLRootCert),
		Migrations:  postgres.Migrations,
	}
	return config{
		dbConfig:    dbConfig,
		authTLS:     tls,
		authTimeout: authTimeout,
		logLevel:    env.Load(envLogLevel, defLogLevel),
		httpPort:    env.Load(envHTTPPort, defHTTPPort),
		serverCert:  env.Load(envServerCert, defServerCert),
		serverKey:   env.Load(envServerKey, defServerKey),
		authCACerts: env.Load(envAuthCACerts, defAuthCACerts),
		jaegerURL:   env.Load(envJaegerURL, defJaegerURL),
		authURL:     env.Load(envAuthURL, defAuthURL),
	}
}

func main() {
	cfg := loadConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)
	l, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}
	db, err := db.Connect(cfg.dbConfig)
	if err != nil {
		log.Fatalf(err.Error())
	}
	authTracer, closer := initJaeger("auth", cfg.jaegerURL, l)
	defer closer.Close()

	auth, close := connectToAuth(cfg, authTracer, l)
	if close != nil {
		defer close()
	}

	repo := postgres.NewRepository(db)
	idp := uuid.New()
	svc := computations.NewService(repo, idp, auth)
	svc = api.LoggingMiddleware(svc, l)
	h := api.MakeHandler(svc, nil, l)

	g.Go(func() error {
		return http.StartServer(ctx, svcName, cfg.httpPort, cfg.serverCert, cfg.serverKey, h, l)
	})
	g.Go(errors.Handle(svcName, l, ctx, cancel))
	if err := g.Wait(); err != nil {
		l.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
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
		logger.Error(fmt.Sprintf("Failed to init Jaeger: %s", err))
		os.Exit(1)
	}

	return tracer, closer
}

func connectToAuth(cfg config, tracer opentracing.Tracer, logger logger.Logger) (clients.AuthServiceClient, func() error) {
	var opts []grpc.DialOption
	if cfg.authTLS {
		if cfg.authCACerts != "" {
			tpc, err := credentials.NewClientTLSFromFile(cfg.authCACerts, "")
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create tls credentials: %s", err))
				os.Exit(1)
			}
			opts = append(opts, grpc.WithTransportCredentials(tpc))
		}
	} else {
		opts = append(opts, grpc.WithInsecure())
		logger.Info("gRPC communication is not encrypted")
	}

	conn, err := grpc.Dial(cfg.authURL, opts...)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to connect to auth service: %s", err))
		os.Exit(1)
	}
	return authapi.NewClient(tracer, conn, cfg.authTimeout), conn.Close
}
