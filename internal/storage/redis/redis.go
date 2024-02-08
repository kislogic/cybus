package redis

import (
	"context"
	"cybus/internal/dto"
	"fmt"
	"time"

	"go.uber.org/zap"
)

const (
	redisProvider              = "redis"
	defaultReconnectionTimeout = 5
)

// Credentials is an option structure for configuring real cache implementation.
type Credentials struct {
	Active string `yaml:"active"`
	Redis  struct {
		Address  string `yaml:"address"`
		Password string `yaml:"password"`
		PoolSize int    `yaml:"poolSize"`
	} `yaml:"redis"`
}

// ConnectLoop takes config and depending on cache section of config wraps actual cache implementation
// It's trying to connect to cache in a loop because at least at dev environment service can be ready before cache is up.
func ConnectLoop(ctx context.Context, config Credentials, logger *zap.Logger) (cache dto.Cache, closeFunc func() error, err error) {
	switch activeCache := config.Active; activeCache {
	case redisProvider:
		return openRedisClient(ctx, config, logger)
	default:
		return openRedisClient(ctx, config, logger)
	}
}

// Cache wraps *redis.Client to meet swappable Cache interface.
type Cache struct {
	Client *redis.Client
}

// newRedisCache accept config and returns ready for usage cache among with its closer.
func openRedisClient(ctx context.Context, config Credentials, logger *zap.Logger) (redisCache *Cache, closeFunc func() error, err error) {

	opts := &redis.Options{
		Addr:               config.Redis.Address,
		Password:           config.Redis.Password,
		PoolSize:           config.Redis.PoolSize,
		IdleTimeout:        55 * time.Second,
		IdleCheckFrequency: 170 * time.Second,
	}
	client := redis.NewClient(opts)

	err = client.WithContext(ctx).Ping(ctx).Err()
	if nil == err {
		redisCache := &Cache{Client: client}
		return redisCache, client.Close, nil
	}

	logger.Error("error when starting redis server", zap.Error(err))

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	timeoutExceeded := time.After(time.Second * time.Duration(defaultReconnectionTimeout))

	for {

		select {

		case <-timeoutExceeded:
			return nil, nil, fmt.Errorf("redis: cache connection failed after %s timeout", time.Second*time.Duration(defaultReconnectionTimeout))

		case <-ticker.C:
			err := client.Ping(ctx).Err()
			if nil == err {
				redisCache := &Cache{Client: client}
				return redisCache, redisCache.Client.Close, nil
			}
			logger.Error("redis: error when starting server", zap.Error(err))

		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

// Get retrieves value from Redis and serializes to pointer value.
func (c *Cache) Get(ctx context.Context, key string, ptrValue interface{}) error {
	b, err := c.Client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return dto.ErrCacheMiss
		}
		return fmt.Errorf("redis: problem while trying to get value from cache: %w", err)
	}
	return dto.Deserialize(b, ptrValue)
}

func (c *Cache) Del(ctx context.Context, keys ...string) error {
	if err := c.Client.Del(ctx, keys...).Err(); err != nil {
		if err == redis.Nil {
			return dto.ErrCacheMiss
		}
		return fmt.Errorf("redis: problem while deleting value: %w", err)
	}
	return nil
}

// Set takes key and value as input and setting Redis cache with this value.
func (c *Cache) Set(ctx context.Context, key string, ptrValue interface{}, expires time.Duration) error {

	b, err := dto.Serialize(ptrValue)
	if err != nil {
		return fmt.Errorf("redis: problem while trying to serialize value while setting in cache: %w", err)
	}

	if err := c.Client.Set(ctx, key, b, expires).Err(); err != nil {
		return fmt.Errorf("redis: problem while trying to set value in cache: %w", err)
	}
	return nil
}
