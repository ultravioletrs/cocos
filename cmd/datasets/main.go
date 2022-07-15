package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/ultravioletrs/cocos/datasets"
	"github.com/ultravioletrs/cocos/datasets/api"
	"github.com/ultravioletrs/cocos/datasets/postgres"
	"github.com/ultravioletrs/cocos/internal/db"
	"github.com/ultravioletrs/cocos/internal/env"
	"github.com/ultravioletrs/cocos/internal/errors"
	"github.com/ultravioletrs/cocos/internal/http"
	"golang.org/x/sync/errgroup"
)

const (
	defLogLevel      = "debug"
	defDBHost        = "localhost"
	defDBPort        = "5432"
	defDBUser        = "cocos"
	defDBPass        = "cocos"
	defDB            = "datasets"
	defDBSSLMode     = "disable"
	defDBSSLCert     = ""
	defDBSSLKey      = ""
	defDBSSLRootCert = ""
	defHTTPPort      = "9000"
	defServerCert    = ""
	defServerKey     = ""

	defAuthTLS     = "false"
	defAuthCACerts = ""
	defAuthURL     = "localhost:8181"
	defAuthTimeout = "1s"

	envLogLevel      = "COCOS_DATASETS_LOG_LEVEL"
	envDBHost        = "COCOS_DATASETS_DB_HOST"
	envDBPort        = "COCOS_DATASETS_DB_PORT"
	envDBUser        = "COCOS_DATASETS_DB_USER"
	envDBPass        = "COCOS_DATASETS_DB_PASS"
	envDB            = "COCOS_DATASETS_DB"
	envDBSSLMode     = "COCOS_DATASETS_DB_SSL_MODE"
	envDBSSLCert     = "COCOS_DATASETS_DB_SSL_CERT"
	envDBSSLKey      = "COCOS_DATASETS_DB_SSL_KEY"
	envDBSSLRootCert = "COCOS_DATASETS_DB_SSL_ROOT_CERT"
	envHTTPPort      = "COCOS_DATASETS_HTTP_PORT"
	envServerCert    = "COCOS_DATASETS_SERVER_CERT"
	envServerKey     = "COCOS_DATASETS_SERVER_KEY"

	envAuthTLS     = "MF_AUTH_CLIENT_TLS"
	envAuthCACerts = "MF_AUTH_CA_CERTS"
	envAuthURL     = "MF_AUTH_GRPC_URL"
	envAuthTimeout = "MF_AUTH_GRPC_TIMEOUT"
)

const svcName = "Datasets"

type config struct {
	logLevel    string
	dbConfig    db.Config
	httpPort    string
	serverCert  string
	serverKey   string
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

	repo := postgres.NewRepository(db)
	idp := uuid.New()
	svc := datasets.NewService(repo, idp)
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
