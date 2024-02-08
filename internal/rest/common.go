package rest

import (
	"context"
	"cybus/internal/dto"
	"cybus/internal/rest/middleware"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
)

func decode(request *http.Request, val interface{}) error {
	dec := json.NewDecoder(request.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(val)
}

func getUser(ctx context.Context) *dto.User {
	return ctx.Value(middleware.UserCtxKey).(*dto.User)
}

func getSession(ctx context.Context) *dto.Session {
	return ctx.Value(middleware.SessionCtxKey).(*dto.Session)
}

func getLocale(ctx context.Context) string {
	return ctx.Value(middleware.UserCtxKey).(*dto.User).RequestLocale
}

func parseIntParam(r *http.Request, name string) (int, error) {
	str, err := parseParam(r, name)
	if err != nil {
		return 0, err
	}
	result, err := strconv.Atoi(str)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func parseParam(r *http.Request, name string) (string, error) {
	if result := chi.URLParam(r, name); result != "" {
		return result, nil
	}
	return "", fmt.Errorf("%s is required", name)
}
