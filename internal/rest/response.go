package rest

import "cybus/internal/dto"

var (
	reasonDecoding        = "decoding"
	reasonValidation      = "validation"
	reasonBan             = "ban"
	reasonConflict        = "conflict"
	reasonSlowDown        = "slowDown"
	reasonInternalError   = "internalError"
	reasonTooManyAttempts = "tooManyAttempts"
)

var statusOk = "ok"

type Response struct {
	Status string      `json:"status"`
	Result interface{} `json:"result"`
}

type baseResponse struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason,omitempty"`
}

func NewRESTResponse(result interface{}) *Response {
	return &Response{Result: result, Status: statusOk}
}

// Error is constructed when REST API responds with response not equal to 200.
type Error struct {
	Status           string               `json:"status"`
	ErrorMessage     string               `json:"errorMessage"`
	ValidationErrors *dto.ValidationError `json:"validationErrors,omitempty"`
}

// NewRESTError constructs error object for REST response.
func NewRESTError(status string, errorMessage string) *Error {
	return newRESTError(status, errorMessage, nil)
}

// NewRESTValidationError constructs error object for REST response accepting additional validation problem description.
func NewRESTValidationError(status string, errorMessage string, validationErr *dto.ValidationError) *Error {
	return newRESTError(status, errorMessage, validationErr)
}

func newRESTError(status string, errorMessage string, validationErrors *dto.ValidationError) *Error {
	return &Error{
		Status:           status,
		ErrorMessage:     errorMessage,
		ValidationErrors: validationErrors,
	}
}
