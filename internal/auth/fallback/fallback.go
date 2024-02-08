package fallback

import (
	"context"
	"cybus/internal/dto"
	"errors"
	"time"

	"go.uber.org/zap"
)

type fallbackAuthProvider struct {
	authDuration   time.Duration // how much time we give to auth, to prevent latency
	cache          dto.Cache
	sessionStorage dto.SessionStorage
	logger         *zap.Logger
}

// NewFallbackAuthProvider returns auth provider based on redis with a fallback to mysql.
func NewFallbackAuthProvider(
	authDuration time.Duration,
	cache dto.Cache,
	sessionStorage dto.SessionStorage,
	logger *zap.Logger) (dto.AuthProvider, error) {
	if authDuration == 0 {
		return nil, errors.New("fallback auth: auth duration must be explicitly set")
	}
	if cache == nil {
		return nil, errors.New("fallback auth: provided cache to auth provider is nil")
	}
	if sessionStorage == nil {
		return nil, errors.New("fallback auth: provided session storage to auth provider is nil")
	}
	if logger == nil {
		return nil, errors.New("fallback auth: provided logger to auth provider is nil")
	}
	return &fallbackAuthProvider{
		authDuration:   authDuration,
		cache:          cache,
		sessionStorage: sessionStorage,
		logger:         logger}, nil
}

// Authenticate retrieves session from Redis with a fallback to mysql storage.
func (n *fallbackAuthProvider) Authenticate(ctx context.Context, token string) (*dto.Session, error) {

	opCtx, cancel := context.WithTimeout(ctx, n.authDuration)
	defer cancel()

	// first, check in distributed cache
	key := dto.Sessions + token
	session := &dto.Session{}
	err := n.cache.Get(opCtx, key, session)
	switch {
	case nil == err:
		return session, nil
	case errors.Is(err, context.Canceled):
		return nil, err
	case !errors.Is(err, dto.ErrCacheMiss):
		n.logger.Error("fallback auth provider: problem while retrieving session by session token", zap.Error(err))
	}

	session, err = n.sessionStorage.GetSession(ctx, token)
	if err != nil {
		return nil, err
	}

	if session.User.IsBanned {
		return nil, dto.ErrUserIsBanned
	}

	if session.Disabled {
		return nil, dto.ErrSessionAlreadyDeactivated
	}

	if err := n.cache.Set(ctx, key, &session, 0); err != nil {
		n.logger.Error("fallback auth provider: problem while trying to set session to cache", zap.Error(err))
	}

	return session, nil

}
