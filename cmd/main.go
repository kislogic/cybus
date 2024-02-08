package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"cybus/internal/auth"
	"cybus/internal/config"
	"cybus/internal/dto"
	"cybus/internal/ipgeolocation"
	mockOtp "cybus/internal/mock/otp"
	"cybus/internal/rest"
	"cybus/internal/rest/respond"
	"cybus/internal/storage/mysql"
	"cybus/internal/storage/redis"
	"cybus/internal/svc/authentication"
	"cybus/internal/svc/session"

	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/pressly/goose"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {

	const failed = 1
	logger, atomicLevel, err := config.NewLogger()
	if err != nil {
		fmt.Printf("failed to create logger: %s\n", err)
		os.Exit(failed)
	}

	if err := run(logger, atomicLevel); err != nil {
		logger.Error("web server start / shutdown problem", zap.Error(err))
		os.Exit(failed)
	}

}

// run performs the following things:
// 1. Construct all dependencies, such as database, cache pools, external clients
// 2. Wraps them to handy abstractions, such as services and repositories
// 3. Pass dependencies to router and glue everything with http.Host
// 4. Starts http.Host with dependencies and manages graceful shutdown.
func run(logger *zap.Logger, atomicLevel zap.AtomicLevel) error {

	defer func() {
		_ = logger.Sync()
	}()

	rand.Seed(time.Now().Unix())

	configSource := flag.String("c", "", "path for config file")
	flag.Parse()
	cfg, err := config.NewConfig(*configSource)
	if err != nil {
		return fmt.Errorf("config initialization problem: %w", err)
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt)
	termCtx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := <-term
		logger.Info("signal was received", zap.Stringer("sig", sig))
		cancel()
	}()

	// DEBUG < INFO < WARN < ERROR < DPanic < PANIC < FATAL
	levels := map[string]zapcore.Level{
		"debug":  zap.DebugLevel,
		"info":   zap.InfoLevel,
		"error":  zap.ErrorLevel,
		"dpanic": zap.DPanicLevel,
		"panic":  zap.PanicLevel,
		"fatal":  zap.FatalLevel,
	}

	atomicLevel.SetLevel(levels[strings.ToLower(cfg.Logger.Level)])

	db, closeDB, err := mysql.ConnectLoop(termCtx, cfg.Database, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeDB(); err != nil {
			logger.Error("problem occurred while closing database connection pool during server shutdown", zap.Error(err))
		}
	}()

	migrations := cfg.Migrations
	if migrations.Enabled {
		goose.SetLogger(zap.NewStdLog(logger.With(zap.String("service", "goose"))))
		if err := goose.SetDialect(migrations.Dialect); err != nil {
			return fmt.Errorf("goose problem while setting dialect: %w", err)
		}
		goose.SetTableName(migrations.Table)
		goose.SetVerbose(migrations.Verbose)
		if err := goose.Up(db, migrations.Directory); err != nil {
			return fmt.Errorf("goose migration failed: %w", err)
		}
	}

	cache, closeCache, err := redis.ConnectLoop(termCtx, cfg.Cache, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeCache(); err != nil {
			logger.Error("problem occurred while closing cache connection pool during server shutdown", zap.Error(err))
		}
	}()

	app, err := newrelic.NewApplication(
		newrelic.ConfigDistributedTracerEnabled(false),
		newrelic.ConfigEnabled(false),
		newrelic.ConfigAppName("app"),
		newrelic.ConfigLicense("eu01xxc0ec28ee245237be650a9151822507NRAL"),
		newrelic.ConfigDistributedTracerEnabled(true),
	)
	if err != nil {
		return fmt.Errorf("tracing: problem while initializing new relic: %w", err)
	}

	// let's define some interfaces that encapsulate database interactions here
	var (
		userStorage                dto.UserStorage
		sessionStorage             dto.SessionStorage
		userSessionStorage         dto.UserSessionStorage
		sessionDeactivationStorage dto.SessionDeactivationsStorage
	)

	userStorage, err = mysql.NewUserStorage(db)
	if err != nil {
		return err
	}

	sessionStorage, err = mysql.NewSessionStorage(db)
	if err != nil {
		return err
	}

	sessionDeactivationStorage, err = mysql.NewSessionDeactivationStorage(db)
	if err != nil {
		return err
	}

	userSessionStorage, err = mysql.NewUserSessionStorage(db)
	if err != nil {
		return err
	}

	// let's define some services that contain business-logic here
	var (
		authenticationService dto.AuthenticationService
		sessionService        dto.SessionService
	)

	startUOW := mysql.NewUOW(db, logger.With(zap.String("service", "uow")))

	var otpVerifier dto.OTPVerifier
	otpVerifier, err = chooseOTPVerifier(cfg, logger)
	if err != nil {
		return err
	}

	ipGeoClient, err := ipgeolocation.NewIPGeoLocationClient(
		"2cabc0bc9fce42f4aa4e5948f93859ed",
		"https://api.ipgeolocation.io/",
		&http.Client{Timeout: time.Second * 2},
		/*rps */ 200,
		zap.NewStdLog(logger),
	)
	if err != nil {
		return err
	}

	sessionService, err = session.NewSessionService(
		userSessionStorage,
		sessionDeactivationStorage,
		startUOW,
		&session.DisabledMethods{},
		&session.Timeouts{DeactivateSession: time.Millisecond * 450, ListUserSessions: time.Millisecond * 450},
		cache,
		logger,
	)
	if err != nil {
		return err
	}

	authenticationService, err = authentication.NewAuthenticationService(
		userStorage,
		sessionStorage,
		cache,
		startUOW,
		&authentication.Verification{CompanyName: "ShoutDEMO", Verifier: otpVerifier},
		ipGeoClient,
		logger)
	if err != nil {
		return err
	}

	const authProviderName = "redis-fallback-mysql"
	authProvider, err := auth.NewAuthProvider(&auth.Config{
		Provider:       authProviderName,
		Cache:          cache,
		SessionStorage: sessionStorage,
		Logger:         logger})
	if err != nil {
		return err
	}

	responder, err := respond.NewResponder()
	if err != nil {
		return err
	}

	apiHandler, err := rest.NewAPIHandler(&rest.APIBackend{
		NewRelicAPP:           app,
		AuthProvider:          authProvider,
		AuthenticationService: authenticationService,
		SessionService:        sessionService,

		Respond: responder,
		Logger:  logger,
	})
	if err != nil {
		return err
	}

	port := fmt.Sprint(cfg.Server.Port)
	srv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Host, port),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler:           apiHandler,
		ErrorLog:          zap.NewStdLog(logger.With(zap.String("service", "http"))),
	}
	go func() {
		if err = srv.ListenAndServe(); err != nil && !errors.Is(http.ErrServerClosed, err) {
			logger.Error("problem while starting listening on specified port", zap.Error(err))
			cancel()
		}
	}()

	logger.Info("server started",
		zap.String("port", port),
		zap.String("runtime", runtime.Version()),
		zap.String("os", runtime.GOOS))

	<-termCtx.Done()

	logger.Info("server stopped")

	app.Shutdown(5 * time.Second)

	ctxShutDown, cancel := context.WithTimeout(context.Background(), cfg.Server.CloseTimeout)
	defer func() {
		cancel()
	}()

	if err = srv.Shutdown(ctxShutDown); err != nil {
		return fmt.Errorf("server graceful shutdown failed: %w", err)
	}

	logger.Info("server exited properly")

	return nil

}

func chooseOTPVerifier(config *config.Config, _ *zap.Logger) (dto.OTPVerifier, error) {
	switch config.OTP.Active {
	default:
		return mockOtp.NewOTPMock(config.OTP.Mock.ReferenceID, config.OTP.Mock.Pin)
	}
}
