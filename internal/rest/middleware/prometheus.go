package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	chimw "github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

const statusClientClosedRequest = "499"

type PrometheusRequests struct {
	requestCount        *prometheus.CounterVec
	requestSLOLatencies *prometheus.HistogramVec
}

func NewPrometheusRequests() (*PrometheusRequests, error) {
	labels := []string{"code", "method", "path"}
	var m PrometheusRequests
	m.requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "How many http requests processed, partitioned by code, method, path.",
	}, labels)
	m.requestSLOLatencies = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "request_slo_duration_seconds",
			Help:    "Response latency distribution in seconds for each code, method, path.",
			Buckets: []float64{0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 45, 60},
		},
		labels)
	if err := prometheus.Register(m.requestCount); err != nil {
		return nil, fmt.Errorf("prometheus requests middleware: prolem while register requests counter: %w", err)
	}
	if err := prometheus.Register(m.requestSLOLatencies); err != nil {
		return nil, fmt.Errorf("prometheus requests middleware: prolem while register requests histogram: %w", err)
	}
	return &m, nil
}

func (m *PrometheusRequests) CountRequests(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		now := time.Now()

		rw := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(rw, r)

		status := rw.Status()
		code := strconv.Itoa(status)
		if status == 0 && errors.Is(r.Context().Err(), context.Canceled) {
			code = statusClientClosedRequest
		}

		labels := prometheus.Labels{
			"code":   code,
			"method": r.Method,
			"path":   chi.RouteContext(r.Context()).RoutePattern(),
		}
		elapsedSeconds := time.Since(now).Seconds()

		m.requestCount.With(labels).Inc()
		m.requestSLOLatencies.With(labels).Observe(elapsedSeconds)

	})
}
