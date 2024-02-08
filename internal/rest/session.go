package rest

import (
	"context"
	"cybus/internal/dto"
	"cybus/internal/rest/middleware"
	"cybus/internal/rest/respond"
	"errors"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/newrelic/go-agent/v3/newrelic"
	"go.uber.org/zap"
)

type deactivateSessionResponse struct {
	Success    bool   `json:"success"`
	Reason     string `json:"reason,omitempty"`
	MustLogout bool   `json:"mustLogout"`
}

type userSessionsResponse struct {
	Success  bool               `json:"success"`
	Sessions []*dto.UserSession `json:"sessions"`
	Reason   string             `json:"reason,omitempty"`
}

// newSessionBackend returns a new instance of sessionBackend.
func newSessionBackend(b *APIBackend) *sessionBackend {
	return &sessionBackend{
		sessionService: b.SessionService,
		respond:        b.Respond,
		logger:         b.Logger.With(zap.String("handler", "sessions")),
	}
}

func newSessionHandler(b *sessionBackend) *sessionHandler {
	return &sessionHandler{
		sessionService: b.sessionService,
		respond:        b.respond,
		logger:         b.logger}
}

type sessionBackend struct {
	sessionService dto.SessionService
	respond        *respond.Responder
	logger         *zap.Logger
}

type sessionHandler struct {
	sessionService dto.SessionService
	respond        *respond.Responder
	logger         *zap.Logger
}

func (h *sessionHandler) routes(nrapp *newrelic.Application, auth *middleware.Authentication, locale *middleware.AcceptLanguageSetter) chi.Router {

	r := chi.NewRouter()
	r.Use(auth.Authenticate)
	r.Use(locale.SetLocale)

	_, listUserSessionsH := newrelic.WrapHandleFunc(nrapp, "/", h.handleListUserSessions)
	_, deactivateUserSessionH := newrelic.WrapHandleFunc(nrapp, "/deactivate-session", h.handleDeactivateUserSession)
	r.Get("/", listUserSessionsH)
	r.Patch("/{id}", deactivateUserSessionH)

	return r
}

func (h *sessionHandler) handleListUserSessions(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	user := getUser(ctx)

	res, err := h.sessionService.ListUserSessions(ctx, user)
	if err != nil {
		var validationErr *dto.ValidationError
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.As(err, &validationErr):
			h.logger.Warn("list user sessions: validation problem occurred",
				zap.String("ip", r.RemoteAddr),
				zap.Errors("internal", validationErr.InternalErrors), zap.Error(err))
			h.respond.BadRequest(w, NewRESTValidationError(reasonValidation, "problem while validating request", validationErr))
			return
		case errors.Is(err, dto.ErrRateLimit):
			h.respond.Ok(w, NewRESTResponse(&userSessionsResponse{Reason: "rateLimit", Success: false, Sessions: []*dto.UserSession{}}))
			return
		case errors.Is(err, dto.ErrGeneralServiceDisabled):
			h.respond.Ok(w, NewRESTResponse(&userSessionsResponse{Reason: "disabledSvc", Success: false, Sessions: []*dto.UserSession{}}))
			return
		default:
			h.logger.Error("list user sessions: service problem while trying to list user sessions",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err))
			h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
			return
		}
	}

	if res == nil {
		res = []*dto.UserSession{}
	}

	h.respond.Ok(w, NewRESTResponse(&userSessionsResponse{Success: true, Sessions: res}))

}

func (h *sessionHandler) handleDeactivateUserSession(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	session := getSession(ctx)
	user := session.User

	sessionID := chi.URLParam(r, "id")

	mustLogout, err := h.sessionService.DeactivateSession(ctx, sessionID, user, session, r.RemoteAddr)
	if err != nil {
		var validationErr *dto.ValidationError
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.Is(err, context.DeadlineExceeded):
			h.logger.Error("deactivate session: server is responding too slow", zap.Error(err))
			h.respond.Ok(w, NewRESTResponse(&deactivateSessionResponse{Reason: "slowSvc", Success: false}))
			return
		case errors.As(err, &validationErr):
			h.logger.Warn("deactivate session: validation problem occurred",
				zap.String("ip", r.RemoteAddr),
				zap.Uint64("userID", uint64(user.ID)),
				zap.String("sessionID", sessionID),
				zap.Errors("internal", validationErr.InternalErrors), zap.Error(err))
			h.respond.BadRequest(w, NewRESTValidationError(reasonValidation, "problem while validating request", validationErr))
			return
		case errors.Is(err, dto.ErrSessionAlreadyDeactivated):
			h.respond.Ok(w, NewRESTResponse(&deactivateSessionResponse{Reason: "sessionAlreadyDeactivated", Success: false}))
			return
		case errors.Is(err, dto.ErrGeneralServiceDisabled):
			h.respond.Ok(w, NewRESTResponse(&deactivateSessionResponse{Reason: "disabledSvc", Success: false}))
			return
		default:
			h.logger.Error("deactivate session: service problem while try to disable session",
				zap.String("ip", r.RemoteAddr),
				zap.String("sessionID", sessionID),
				zap.Uint64("userID", uint64(user.ID)),
				zap.Error(err))
			h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
			return
		}
	}

	h.respond.Ok(w, NewRESTResponse(&deactivateSessionResponse{Success: true, MustLogout: mustLogout}))

}
