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
	"github.com/ultravioletrs/cocos/computations"
	repo "github.com/ultravioletrs/cocos/computations/postgres"
	"github.com/ultravioletrs/cocos/internal/env"
	"github.com/ultravioletrs/cocos/internal/postgres"
	"golang.org/x/sync/errgroup"
)

const (
	defLogLevel      = "error"
	defDBHost        = "localhost"
	defDBPort        = "5432"
	defDBUser        = "cocos"
	defDBPass        = "cocos"
	defDB            = "computations"
	defDBSSLMode     = "disable"
	defDBSSLCert     = ""
	defDBSSLKey      = ""
	defDBSSLRootCert = ""
	defHTTPPort      = "8180"
	defServerCert    = ""
	defServerKey     = ""

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

	envAuthTLS     = "MF_AUTH_CLIENT_TLS"
	envAuthCACerts = "MF_AUTH_CA_CERTS"
	envAuthURL     = "MF_AUTH_GRPC_URL"
	envAuthTimeout = "MF_AUTH_GRPC_TIMEOUT"
)

type config struct {
	logLevel    string
	dbConfig    postgres.Config
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

	dbConfig := postgres.Config{
		Host:        env.Load(envDBHost, defDBHost),
		Port:        env.Load(envDBPort, defDBPort),
		User:        env.Load(envDBUser, defDBUser),
		Pass:        env.Load(envDBPass, defDBPass),
		Name:        env.Load(envDB, defDB),
		SSLMode:     env.Load(envDBSSLMode, defDBSSLMode),
		SSLCert:     env.Load(envDBSSLCert, defDBSSLCert),
		SSLKey:      env.Load(envDBSSLKey, defDBSSLKey),
		SSLRootCert: env.Load(envDBSSLRootCert, defDBSSLRootCert),
		Migrations:  repo.Migrations,
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
	fmt.Println(g)

	logger, err := logger.New(os.Stdout, cfg.logLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}
	fmt.Println("hello")
	db, err := postgres.Connect(cfg.dbConfig)
	if err != nil {
		log.Fatalf(err.Error())
	}

	repo := repo.NewRepository(db)
	c := computations.NewService(repo)
	fmt.Println("hello:", c)
	logger.Info("all good")
}

// func main() {
// 	ctx, cancel := context.WithCancel(context.Background())
// 	g, ctx := errgroup.WithContext(ctx)

// 	logger, err := logger.New(os.Stdout, cfg.logLevel)
// 	if err != nil {
// 		log.Fatalf(err.Error())
// 	}
// 	db := connectToDB(cfg.dbConfig, logger)
// 	defer db.Close()

// 	authTracer, closer := initJaeger("auth", cfg.jaegerURL, logger)
// 	defer closer.Close()

// 	auth, close := connectToAuth(cfg, authTracer, logger)
// 	if close != nil {
// 		defer close()
// 	}

// 	tracer, closer := initJaeger("users", cfg.jaegerURL, logger)
// 	defer closer.Close()

// 	dbTracer, dbCloser := initJaeger("users_db", cfg.jaegerURL, logger)
// 	defer dbCloser.Close()

// 	svc := newService(db, dbTracer, auth, cfg, logger)

// 	g.Go(func() error {
// 		return startHTTPServer(ctx, tracer, svc, cfg.httpPort, cfg.serverCert, cfg.serverKey, logger)
// 	})

// 	g.Go(func() error {
// 		if sig := errors.SignalHandler(ctx); sig != nil {
// 			cancel()
// 			logger.Info(fmt.Sprintf("Users service shutdown by signal: %s", sig))
// 		}
// 		return nil
// 	})

// 	if err := g.Wait(); err != nil {
// 		logger.Error(fmt.Sprintf("Users service terminated: %s", err))
// 	}
// }

// func connectToDB(dbConfig postgres.Config, logger logger.Logger) *sqlx.DB {
// 	db, err := postgres.Connect(dbConfig)
// 	if err != nil {
// 		logger.Error(fmt.Sprintf("Failed to connect to postgres: %s", err))
// 		os.Exit(1)
// 	}
// 	return db
// }

// func connectToAuth(cfg config, tracer opentracing.Tracer, logger logger.Logger) (mainflux.AuthServiceClient, func() error) {
// 	var opts []grpc.DialOption
// 	if cfg.authTLS {
// 		if cfg.authCACerts != "" {
// 			tpc, err := credentials.NewClientTLSFromFile(cfg.authCACerts, "")
// 			if err != nil {
// 				logger.Error(fmt.Sprintf("Failed to create tls credentials: %s", err))
// 				os.Exit(1)
// 			}
// 			opts = append(opts, grpc.WithTransportCredentials(tpc))
// 		}
// 	} else {
// 		opts = append(opts, grpc.WithInsecure())
// 		logger.Info("gRPC communication is not encrypted")
// 	}

// 	conn, err := grpc.Dial(cfg.authURL, opts...)
// 	if err != nil {
// 		logger.Error(fmt.Sprintf("Failed to connect to auth service: %s", err))
// 		os.Exit(1)
// 	}

// 	return authapi.NewClient(tracer, conn, cfg.authTimeout), conn.Close
// }

// func newService(db *sqlx.DB, tracer opentracing.Tracer, auth mainflux.AuthServiceClient, c config, logger logger.Logger) users.Service {
// 	database := postgres.NewDatabase(db)
// 	hasher := bcrypt.New()
// 	userRepo := tracing.UserRepositoryMiddleware(postgres.NewUserRepo(database), tracer)

// 	emailer, err := emailer.New(c.resetURL, &c.emailConf)
// 	if err != nil {
// 		logger.Error(fmt.Sprintf("Failed to configure e-mailing util: %s", err.Error()))
// 	}

// 	idProvider := uuid.New()

// 	svc := users.New(userRepo, hasher, auth, emailer, idProvider, c.passRegex)
// 	svc = api.LoggingMiddleware(svc, logger)
// 	svc = api.MetricsMiddleware(
// 		svc,
// 		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
// 			Namespace: "users",
// 			Subsystem: "api",
// 			Name:      "request_count",
// 			Help:      "Number of requests received.",
// 		}, []string{"method"}),
// 		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
// 			Namespace: "users",
// 			Subsystem: "api",
// 			Name:      "request_latency_microseconds",
// 			Help:      "Total duration of requests in microseconds.",
// 		}, []string{"method"}),
// 	)
// 	if err := createAdmin(svc, userRepo, c, auth); err != nil {
// 		logger.Error("failed to create admin user: " + err.Error())
// 		os.Exit(1)
// 	}

// 	switch c.selfRegister {
// 	case true:
// 		// If MF_USERS_ALLOW_SELF_REGISTER environment variable is "true",
// 		// everybody can create a new user. Here, check the existence of that
// 		// policy. If the policy does not exist, create it; otherwise, there is
// 		// no need to do anything further.
// 		_, err := auth.Authorize(context.Background(), &mainflux.AuthorizeReq{Obj: "user", Act: "create", Sub: "*"})
// 		if err != nil {
// 			// Add a policy that allows anybody to create a user
// 			apr, err := auth.AddPolicy(context.Background(), &mainflux.AddPolicyReq{Obj: "user", Act: "create", Sub: "*"})
// 			if err != nil {
// 				logger.Error("failed to add the policy related to MF_USERS_ALLOW_SELF_REGISTER: " + err.Error())
// 				os.Exit(1)
// 			}
// 			if !apr.GetAuthorized() {
// 				logger.Error("failed to authorized the policy result related to MF_USERS_ALLOW_SELF_REGISTER: " + errors.ErrAuthorization.Error())
// 				os.Exit(1)
// 			}
// 		}
// 	default:
// 		// If MF_USERS_ALLOW_SELF_REGISTER environment variable is "false",
// 		// everybody cannot create a new user. Therefore, delete a policy that
// 		// allows everybody to create a new user.
// 		dpr, err := auth.DeletePolicy(context.Background(), &mainflux.DeletePolicyReq{Obj: "user", Act: "create", Sub: "*"})
// 		if err != nil {
// 			logger.Error("failed to delete a policy: " + err.Error())
// 			os.Exit(1)
// 		}
// 		if !dpr.GetDeleted() {
// 			logger.Error("deleting a policy expected to succeed.")
// 			os.Exit(1)
// 		}
// 	}

// 	return svc
// }
