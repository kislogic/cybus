// Package mysql implements storage interfaces defined in root package.
package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/newrelic/go-agent/v3/integrations/nrmysql"
	"go.uber.org/zap"
)

const (
	duplicate = 1062
)

// DBConfig contains information sufficient for database connection.
type DBConfig struct {
	Host       string        `yaml:"host"`
	DBName     string        `yaml:"dbName"`
	User       string        `yaml:"user"`
	Password   string        `yaml:"password"`
	PoolConfig PoolConfig    `yaml:"poolConfig"`
	Timeout    time.Duration `yaml:"timeout"` // timeout for trying to connect to the database
	TLS        bool          `yaml:"tls"`
}

// PoolConfig is a db pool configuration.
type PoolConfig struct {
	maxOpenConnections int
	maxIdleConnections int
	maxLifetime        time.Duration
}

// ConnectLoop takes config and specified database credentials as input, returning *sql.DB handle for interactions
// with database.
func ConnectLoop(ctx context.Context, cfg DBConfig, logger *zap.Logger) (db *sql.DB, closeFunc func() error, err error) {

	const (
		timeZone = "UTC"
		net      = "tcp"
	)

	cfg.PoolConfig.maxOpenConnections = 20
	cfg.PoolConfig.maxIdleConnections = 20
	cfg.PoolConfig.maxLifetime = 5 * time.Minute
	cfg.Timeout = time.Second * 3

	if logger == nil {
		return nil, nil, errors.New("mysql: provided logger is nil")
	}

	loc, err := time.LoadLocation(timeZone)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: cannot parse config database TimeZone as IANA time zone value: %w", err)
	}
	conf := mysql.NewConfig()
	conf.Net = net
	conf.Addr = cfg.Host
	conf.User = cfg.User
	conf.Passwd = cfg.Password
	conf.DBName = cfg.DBName
	conf.ParseTime = true
	conf.Timeout = time.Second * 2
	conf.Loc = loc

	dsn := conf.FormatDSN()

	if cfg.TLS {
		dsn += "&tls=true"
	}

	const driverName = "nrmysql"
	if err := mysql.SetLogger(zap.NewStdLog(logger.With(zap.String("service", "mysql")))); err != nil {
		return nil, nil, fmt.Errorf("mysql: problem while setting logger")
	}
	db, err = createDBPool(ctx, driverName, dsn)
	if nil == err {
		configureDBPool(db, cfg.PoolConfig)
		return db, db.Close, nil
	}

	logger.Error("mysql: failed to connect to the database", zap.Error(err))

	if cfg.Timeout == 0 {
		const defaultTimeout = 5
		cfg.Timeout = defaultTimeout
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	timeoutExceeded := time.After(cfg.Timeout)

	for {

		select {

		case <-timeoutExceeded:
			return nil, nil, fmt.Errorf("mysql: db connection failed after %s timeout", cfg.Timeout)

		case <-ticker.C:
			db, err := createDBPool(ctx, driverName, dsn)
			if nil == err {
				configureDBPool(db, cfg.PoolConfig)
				return db, db.Close, nil
			}
			logger.Error("mysql: failed to connect to the database", zap.Error(err))

		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}

}

// createDBPool creates pool of connections to sql server and pings db under the hood.
func createDBPool(ctx context.Context, driverName string, dsn string) (*sql.DB, error) {

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql: problem opening a database specified by its database driver: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("mysql: problem while trying to ping database: %w", err)
	}

	return db, nil

}

// configureDBPool just sets up a database connection pool.
func configureDBPool(db *sql.DB, config PoolConfig) {
	db.SetMaxOpenConns(config.maxOpenConnections)
	db.SetMaxIdleConns(config.maxIdleConnections)
	db.SetConnMaxLifetime(config.maxLifetime)
}
