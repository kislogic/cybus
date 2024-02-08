package middleware

import (
	"bytes"
	"errors"
	"net/http"

	chimw "github.com/go-chi/chi/middleware"
	"go.uber.org/zap"
)

type DebugLogger struct {
	logger *zap.Logger
}

func NewDebugLogger(logger *zap.Logger) (*DebugLogger, error) {
	if logger == nil {
		return nil, errors.New("debug logger: provided logger is nil")
	}
	return &DebugLogger{logger: logger}, nil
}

func (d *DebugLogger) LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		response := bytes.Buffer{}
		rw.Tee(&response)

		next.ServeHTTP(rw, r)

		d.logger.Debug("served request",
			zap.String("method", r.Method),
			zap.String("path", r.RequestURI),
			zap.String("ip", r.RemoteAddr))
	})
}
