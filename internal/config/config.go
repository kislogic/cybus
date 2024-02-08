package config

import (
	"cybus/internal/storage/mysql"
	"cybus/internal/storage/redis"
	"fmt"
	"os"
	"time"
)

// NewConfig is a constructor-like function which
// returns config object filled from YAML file specified in arguments
// if file was not specified it looks for env variable ${CONFIG_FILE}
// if neither argument nor env was specified it tries to look for hardcoded path for conf
// returns error in case of file open error or if config does not comply with invariant.
func NewConfig(configSource string) (*Config, error) {
	const devFilePath = "./config/config.yml"

	// If configSource is empty, check for the environment variable CONFIG_FILE.
	if configSource == "" {
		configSource = os.Getenv("CONFIG_FILE")

		// If CONFIG_FILE environment variable is not set, use the default devFilePath.
		if configSource == "" {
			configSource = devFilePath
		}
	}

	// Read the content of the configuration file.
	confContent, err := os.ReadFile(configSource)
	if err != nil {
		return nil, fmt.Errorf(`warning: configuration file was probably not specified: use flag -c=filename.yml or 'export CONFIG_FILE=conf/filename.yml' while starting %s`, err)
	}

	cfg := &Config{}

	// Expand environment variables in the configuration content.
	confContent = []byte(os.ExpandEnv(string(confContent)))

	// Unmarshal the YAML content into the Config struct.
	if err = yaml.Unmarshal(confContent, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Config contains application level configuration parsed from YAML.
type Config struct {
	Server struct {
		Host         string        `yaml:"host"`
		Port         string        `yaml:"port"`
		CloseTimeout time.Duration `yaml:"closeTimeout"`
	} `yaml:"server"`
	Logger struct {
		Level string `yaml:"level"`
	} `yaml:"logger"`
	Database mysql.DBConfig    `yaml:"database"`
	Cache    redis.Credentials `yaml:"cache"`
	OTP      struct {
		Active string `yaml:"active"`
		Mock   struct {
			ReferenceID string `yaml:"referenceID"`
			Pin         string `yaml:"pin"`
		} `yaml:"mock"`
	} `yaml:"otp"`
	Migrations struct {
		Enabled   bool   `yaml:"enabled"`
		Dialect   string `yaml:"dialect"`
		Table     string `yaml:"table"`
		Directory string `yaml:"directory"`
		Verbose   bool   `yaml:"verbose"`
	} `yaml:"migrations"`
}
