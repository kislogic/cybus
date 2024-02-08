package rest

import (
	"cybus/internal/dto"
	"cybus/internal/rest/middleware"
	"cybus/internal/rest/respond"
	"net/http"
	"strings"
	"time"

	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/go-chi/chi"
	chimw "github.com/go-chi/chi/middleware"

	"go.uber.org/zap"
)

// APIBackend is all services and associated parameters required to construct
// an APIHandler.
type APIBackend struct {
	NewRelicAPP           *newrelic.Application
	AuthenticationService dto.AuthenticationService
	AuthProvider          dto.AuthProvider
	SessionService        dto.SessionService
	Logger                *zap.Logger
	Respond               *respond.Responder
}

// APIHandler is a collection of all the service handlers.
type APIHandler struct {
	chi.Router
}

// NewAPIHandler initialize dependencies and returns router with attached routes.
func NewAPIHandler(b *APIBackend) (*APIHandler, error) {

	r, err := NewBaseChiRouter(b)
	if err != nil {
		return nil, err
	}

	router := &APIHandler{
		Router: r,
	}

	authenticationBackend := newAuthenticationBackend(b)
	authenticationHandler := newAuthenticationHandler(authenticationBackend)

	sessionBackend := newSessionBackend(b)
	sessionHandler := newSessionHandler(sessionBackend)

	authenticationMiddleware, err := middleware.NewAuthentication(b.AuthProvider, b.Respond, b.Logger.With(zap.String("middleware", "authentication")))
	if err != nil {
		return nil, err
	}

	localeMiddleware, err := middleware.NewAcceptLanguageSetter(b.Respond, b.Logger.With(zap.String("middleware", "locale")))
	if err != nil {
		return nil, err
	}

	// RESTy routes for different resources
	router.Route("/api/v1", func(r chi.Router) {
		// sub routers
		r.Mount("/auth", authenticationHandler.routes(b.NewRelicAPP, authenticationMiddleware))
		r.Mount("/sessions", sessionHandler.routes(b.NewRelicAPP, authenticationMiddleware, localeMiddleware))

	})

	return router, nil
}

// NewBaseChiRouter returns a new chi router with a 404 handler, a 405 handler, and a panic handler.
func NewBaseChiRouter(b *APIBackend) (chi.Router, error) {

	router := chi.NewRouter()

	if err := addBaseMiddleware(router, b); err != nil {
		return nil, err
	}

	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	router.Get("/metricsz", promhttp.Handler().ServeHTTP)
	/* router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		api.Err(w, r, &errors.Error{
			Reason: errors.ENotFound,
			Msg:  "path not found",
		})
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		api.Err(w, r, &errors.Error{
			Reason: errors.EMethodNotAllowed,
			Msg:  fmt.Sprintf("allow: %s", w.Header().Get("Allow")),
		})

	})

	*/

	return router, nil
}

func addBaseMiddleware(router *chi.Mux, b *APIBackend) error {

	debugLogger, err := middleware.NewDebugLogger(b.Logger)
	if err != nil {
		return err
	}

	prometheusRequest, err := middleware.NewPrometheusRequests()
	if err != nil {
		return err
	}

	router.Use(chimw.Timeout(time.Millisecond*6000), prometheusRequest.CountRequests, chimw.RealIP, debugLogger.LogRequest)

	return nil

}

// FileServer conveniently sets up a http.FileServer handler to serve
// static files from a http.FileSystem.
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("fileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}
