package dto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

func ContextExpired(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

var ErrIdempotencyConflict = errors.New("duplicate request with the same idempotency key")

// Validator is implemented by request structures.
type Validator interface {
	Validate() error
}

// ValidationError is a type of error occurred during incoming request structure validation.
type ValidationError struct {
	FieldErrors    `json:"errors"`
	InternalErrors `json:"-"`
}

type InternalErrors []error

type FieldErrors []FieldError

func (ve *ValidationError) MarshalJSON() ([]byte, error) {
	return json.Marshal(ve.FieldErrors)
}

// FieldError represents every single validation problem occurred during validation.
// Every problem can affect multiple fields, that's why Fields represents string slice.
type FieldError struct {
	Message string   `json:"message"`
	Fields  []string `json:"fields"`
}

// NewFieldError constructs FieldError.
func NewFieldError(msg string, fields ...string) FieldError {
	return FieldError{
		Message: msg,
		Fields:  fields,
	}
}

func AppendError(err *ValidationError, fieldError FieldError) {
	err.FieldErrors = append(err.FieldErrors, fieldError)
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation problem: field %s", ve.FieldErrors)
}
