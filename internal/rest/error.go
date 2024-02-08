package rest

import (
	"context"
	"cybus/internal/dto"
	"cybus/internal/rest/respond"
	"errors"

	"go.uber.org/zap"
	"net/http"
)

type errorHandler struct {
	handlerName string
	respond     *respond.Responder
	logger      *zap.Logger
}

func newErrorHandler(handlerName string, respond *respond.Responder, logger *zap.Logger) *errorHandler {
	return &errorHandler{
		handlerName: handlerName,
		respond:     respond,
		logger:      logger,
	}
}

func (h *errorHandler) handleRespondErr(w http.ResponseWriter, r *http.Request, err error, fields []zap.Field) {
	var validationErr *dto.ValidationError
	switch {
	case errors.Is(err, context.Canceled):
		return
	case errors.Is(err, context.DeadlineExceeded):
		h.logger.Error(h.handlerName+": server is responding too slow", zap.Error(err))
		h.respond.Ok(w, NewRESTResponse(&baseResponse{Reason: "slowSvc", Success: false}))
		return
	case errors.Is(err, dto.ErrEntityNotFound), errors.Is(err, dto.ErrEntityDeleteNotSuccessful):
		h.respond.Ok(w, NewRESTResponse(&baseResponse{Reason: "NotFound", Success: false}))
		return
	case errors.Is(err, dto.ErrDuplicateEntity):
		h.respond.Ok(w, NewRESTResponse(&baseResponse{Reason: "duplicateEntity", Success: false}))
		return
	case errors.As(err, &validationErr):
		fields = append(fields, zap.String("ip", r.RemoteAddr))
		fields = append(fields, zap.Errors("internal", validationErr.InternalErrors), zap.Error(err))
		h.logger.Warn(h.handlerName+": validation problem occurred", fields...)
		h.respond.BadRequest(w, NewRESTValidationError(reasonValidation, "problem while validating request", validationErr))
		return
	case errors.Is(err, dto.ErrRateLimit):
		h.respond.TooManyRequests(w, NewRESTResponse(&baseResponse{Reason: "rateLimit", Success: false}))
		return
	case errors.Is(err, dto.ErrGeneralServiceDisabled):
		h.respond.Ok(w, NewRESTResponse(&baseResponse{Reason: "disabledSvc", Success: false}))
		return
	default:
		fields = append(fields, zap.String("ip", r.RemoteAddr))
		fields = append(fields, zap.Error(err))
		h.logger.Error(h.handlerName+": service problem", fields...)
		h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
		return
	}
}
