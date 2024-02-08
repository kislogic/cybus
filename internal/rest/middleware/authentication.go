package middleware

import (
	"context"
	"cybus/internal/dto"
	respond2 "cybus/internal/rest/respond"
	"errors"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer, so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

var (
	UserCtxKey    = &contextKey{"User"}
	SessionCtxKey = &contextKey{"Session"}
)

type Authentication struct {
	authProvider dto.AuthProvider
	respond      *respond2.Responder
	logger       *zap.Logger
}

// NewAuthentication is a constructor-like function which creates Authentication middleware.
func NewAuthentication(authProvider dto.AuthProvider, respond *respond2.Responder, logger *zap.Logger) (*Authentication, error) {
	if authProvider == nil {
		return nil, errors.New("authentication middleware: passed auth provider is nil")
	}
	if respond == nil {
		return nil, errors.New("authentication middleware: provided respond is nil")
	}
	if logger == nil {
		return nil, errors.New("authentication middleware: provided logger is nil")
	}
	return &Authentication{authProvider: authProvider, respond: respond, logger: logger}, nil
}

func (m *Authentication) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := TokenFromHeader(r)
		if token == "" {
			m.logger.Warn("empty token on path which must be authenticated", zap.String("path", r.RequestURI), zap.String("ip", r.RemoteAddr))
			m.respond.BadRequest(w, struct {
				Status           string               `json:"status"`
				ErrorMessage     string               `json:"errorMessage"`
				ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
			}{
				Status:       "authentication",
				ErrorMessage: "authorization header doesn't contain bearer token",
			})
			return
		}
		session, err := m.authProvider.Authenticate(r.Context(), token)
		if err != nil {
			switch {
			case errors.Is(err, context.Canceled):
				return
			case errors.Is(err, dto.ErrUserIsBanned):
				m.respond.Forbidden(w, struct {
					Status           string               `json:"status"`
					ErrorMessage     string               `json:"errorMessage"`
					ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
				}{
					Status:       "ban",
					ErrorMessage: "user is banned",
				})
				return

			case errors.Is(err, dto.ErrSessionAlreadyDeactivated):
				m.respond.Forbidden(w, struct {
					Status           string               `json:"status"`
					ErrorMessage     string               `json:"errorMessage"`
					ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
				}{
					Status:       "sessionAlreadyDeactivated",
					ErrorMessage: "user was previously logout from session",
				})
				return

			case errors.Is(err, dto.ErrSessionNotFound):
				m.logger.Warn("session token not found in a database",
					zap.String("token", token),
					zap.Error(err), zap.String("ip", r.RemoteAddr))
				m.respond.BadRequest(w, struct {
					Status           string               `json:"status"`
					ErrorMessage     string               `json:"errorMessage"`
					ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
				}{
					Status:       "authentication",
					ErrorMessage: "not existing session",
				})
				return

			default:
				m.logger.Error("problem while trying to authenticate user", zap.Error(err), zap.String("ip", r.RemoteAddr))
				m.respond.InternalServerError(w, struct {
					Status           string               `json:"status"`
					ErrorMessage     string               `json:"errorMessage"`
					ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
				}{
					Status:       "authentication",
					ErrorMessage: "problem while trying to authenticate user",
				})
				return
			}
		}
		ctx := context.WithValue(r.Context(), UserCtxKey, session.User)
		ctx = context.WithValue(ctx, SessionCtxKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenFromHeader tries to retrieve the token string from the
// "Authorization" request header: "Authorization: BEARER T".
func TokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}
