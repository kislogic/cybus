package middleware

import (
	"context"
	"cybus/internal/dto"
	respond2 "cybus/internal/rest/respond"
	"errors"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/text/language"
)

var (
	// LocaleTagCtxKey contains parsed BCP-47 tag
	LocaleTagCtxKey = &contextKey{"LocaleTag"}
)

type AcceptLanguageSetter struct {
	respond *respond2.Responder
	logger  *zap.Logger
}

func NewAcceptLanguageSetter(responder *respond2.Responder, logger *zap.Logger) (*AcceptLanguageSetter, error) {
	if responder == nil {
		return nil, errors.New("middleware: nil responder was provided to accept language checker")
	}
	if logger == nil {
		return nil, errors.New("middleware: nil logger was provided to accept language checker")
	}
	return &AcceptLanguageSetter{
		respond: responder,
		logger:  logger,
	}, nil
}

func (m *AcceptLanguageSetter) SetLocale(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ctx context.Context
		if locale := r.Header.Get("Accept-Language"); locale == "" {
			m.logger.Warn("Accept-Language header does not contain BCP 47 locale code",
				zap.String("path", r.RequestURI), zap.String("ip", r.RemoteAddr))
			m.respond.BadRequest(w, struct {
				Status           string               `json:"status"`
				ErrorMessage     string               `json:"errorMessage"`
				ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
			}{
				Status:       "locale",
				ErrorMessage: "accept-language header doesn't contain BCP-47 language code",
			})
			return
		} else {
			tag, err := language.Parse(locale)
			if err != nil {
				m.logger.Error("problem while parsing accept language header",
					zap.Error(err),
					zap.String("path", r.RequestURI),
					zap.String("ip", r.RemoteAddr))
				m.respond.BadRequest(w, struct {
					Status           string               `json:"status"`
					ErrorMessage     string               `json:"errorMessage"`
					ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
				}{
					Status:       "locale",
					ErrorMessage: "accept-language must contain valid BCP-47 language code",
				})
				return
			}
			user := r.Context().Value(UserCtxKey).(*dto.User)
			user.RequestLocale = tag.String()
			ctx = context.WithValue(r.Context(), LocaleTagCtxKey, tag)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
