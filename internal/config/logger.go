package config

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger() (*zap.Logger, zap.AtomicLevel, error) {
	conf := zap.NewProductionConfig()
	conf.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	conf.EncoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
	conf.DisableStacktrace = true
	conf.DisableCaller = true
	conf.Encoding = "console"
	conf.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	atomicLevel := zap.NewAtomicLevelAt(zapcore.DebugLevel)
	conf.Level = atomicLevel
	logger, err := conf.Build()
	if err != nil {
		return nil, zap.AtomicLevel{}, fmt.Errorf("failed to build zap logger: %w", err)
	}
	return logger, atomicLevel, nil
}
