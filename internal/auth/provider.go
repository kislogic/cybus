package auth

import (
	"cybus/internal/auth/fallback"
	"cybus/internal/dto"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type Config struct {
	Provider       string `yaml:"provider"`
	Cache          dto.Cache
	Logger         *zap.Logger
	SessionStorage dto.SessionStorage
}

func NewAuthProvider(c *Config) (dto.AuthProvider, error) {

	var (
		p   dto.AuthProvider
		err error
	)

	switch c.Provider {
	case "redis-fallback-mysql":
		p, err = fallback.NewFallbackAuthProvider(time.Millisecond*120, c.Cache, c.SessionStorage, c.Logger)
	default:
		err = fmt.Errorf("auth provider: unknown auth provider: " + c.Provider)
	}

	if err != nil {
		return nil, err
	}

	return p, nil
}
