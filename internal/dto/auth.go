package dto

import (
	"context"
	"errors"
	"regexp"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ttacon/libphonenumber"
)

const (
	Sessions  = "sess:"
	PinExpiry = 60
)

var (
	ErrSessionNotFound        = errors.New("session not found in a database")
	ErrGeneralServiceDisabled = errors.New("service was disabled by system administrator")
)

type AuthProvider interface {
	Authenticate(ctx context.Context, token string) (*Session, error)
}

var (
	ErrUserIsBanned = errors.New("user was banned in the system")
	ErrUserNotFound = errors.New("user not found in persistent database")
	ErrAskForSignIn = errors.New("user confirmed phone on sign up, but was registered before")
)

var ErrCodeExpired = errors.New("login code has expired")

var ErrSignupDisabled = errors.New("sign up is currently disabled by administrator")

var ErrSignInDisabled = errors.New("sign in is currently disabled by administrator")

var ErrRateLimit = errors.New("too much requests from specified ip address")

var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)

var ErrBadCode = errors.New("provided code is wrong")

type OTPVerifierProvider string

const (
	OTPVerifierProviderMock     OTPVerifierProvider = "mock"
	OTPVerifierProviderVonage   OTPVerifierProvider = "vonage"
	OTPVerifierProviderInternal OTPVerifierProvider = "internal"
)

// OTPVerifier is used as an abstraction layer for otp verification provider.
type OTPVerifier interface {
	// RequestOTP sends sms with pin for user authentication.
	RequestOTP(ctx context.Context, phone string, brand string) (resp *RequestOTPResponse, err error)
	// VerifyOTP verifies that provided otp from sms is correct. Returns ErrBadCode in case
	// when provided pin doesn't match.
	VerifyOTP(ctx context.Context, referenceID string, pin string) error
	// Provider verifier name
	Provider() OTPVerifierProvider
}

type RequestOTPResponse struct {
	ReferenceID string
	PinLength   int
}

type SignUpOTPRequest struct {
	Name         string `json:"name"`
	Surname      string `json:"surname"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	OneTimeToken string `json:"oneTimeToken"`
}

type SignInRequest struct {
	Phone          string `json:"phone"`
	IdempotencyKey string `json:"idempotencyKey"`
	IP             string
	ParsedPhone    *libphonenumber.PhoneNumber
}

func (r *SignInRequest) Validate() error {
	result := &ValidationError{}
	phoneNumber, err := libphonenumber.Parse(r.Phone, "")
	if err != nil {
		AppendError(result, NewFieldError("provided phone is not valid", "phone"))
		result.InternalErrors = append(result.InternalErrors, err)
	}
	r.ParsedPhone = phoneNumber

	_, err = uuid.Parse(r.IdempotencyKey)
	if err != nil {
		AppendError(result, NewFieldError("provided idempotency key is not a valid uuid v4", "idempotencyKey"))
		result.InternalErrors = append(result.InternalErrors, err)
	}

	if len(result.FieldErrors) != 0 {
		return result
	}

	return nil
}

type SignUpRequest struct {
	Email          string `json:"email"`
	FullName       string `json:"fullName"`
	Phone          string `json:"phone"`
	Password       string `json:"password"`
	IdempotencyKey string `json:"idempotencyKey"`

	IP string `json:"ip"`

	ParsedPhone *libphonenumber.PhoneNumber
}

type SignInResult SignUpResult

type SignUpResult struct {
	ReferenceID string `json:"referenceID"`
	PinLength   int    `json:"pinLength"`
}

// Validate validates sign up request from the first registration screen.
func (r *SignUpRequest) Validate() error {

	result := &ValidationError{}

	if !isEmailValid(r.Email) {
		AppendError(result, NewFieldError("provided email is not valid", "email"))
	}

	phoneNumber, err := libphonenumber.Parse(r.Phone, "")
	if err != nil {
		AppendError(result, NewFieldError("provided phone is not valid", "phone"))
		result.InternalErrors = append(result.InternalErrors, err)
	}
	r.ParsedPhone = phoneNumber

	passwordLength := utf8.RuneCountInString(r.Password)
	if passwordLength < 8 || passwordLength > 64 {
		AppendError(result, NewFieldError("password length must be from 8 to 64 characters", "password"))
	}

	nameLength := utf8.RuneCountInString(r.FullName)
	if nameLength == 0 || nameLength > 255 {
		AppendError(result, NewFieldError("invalid name length", "fullName"))
	}

	_, err = uuid.Parse(r.IdempotencyKey)
	if err != nil {
		AppendError(result, NewFieldError("provided idempotency key is not a valid uuid v4", "idempotencyKey"))
		result.InternalErrors = append(result.InternalErrors, err)
	}

	if len(result.FieldErrors) != 0 {
		return result
	}

	return nil

}

func isEmailValid(e string) bool {
	return emailRegex.MatchString(e)
}

func (r *SignUpOTPRequest) Validate() error {
	result := &ValidationError{}
	nameLen := utf8.RuneCountInString(r.Name)
	surnameLen := utf8.RuneCountInString(r.Surname)
	if nameLen < 2 || nameLen > 26 {
		AppendError(result, NewFieldError("minimum name length supported by the system is 2, maximum is 26", "name"))
	}
	if surnameLen < 2 || surnameLen > 26 {
		AppendError(result, NewFieldError("minimum surname length supported by the system is 2, maximum is 26", "surname"))
	}
	if len(r.Email) < 3 || len(r.Email) > 320 {
		AppendError(result, NewFieldError("minimum email length supported by the system is 3, maximum is 320", "email"))
	}
	if len(r.Password) < 6 || len(r.Password) > 128 {
		AppendError(result, NewFieldError("password should be more than 6 chars and less than 128", "password"))
	}

	if len(r.OneTimeToken) == 0 {
		AppendError(result, NewFieldError("oneTimeTokenToken is empty", "oneTimeToken"))
	}

	if len(result.FieldErrors) != 0 {
		return result
	}

	return nil
}

type AuthenticationResult struct {
	User  *User
	Token string
}

// AuthenticationService manages user sign up.
type AuthenticationService interface {
	SignIn(ctx context.Context, request *SignInRequest) (result *SignInResult, err error)
	SignUp(ctx context.Context, request *SignUpRequest) (result *SignUpResult, err error)
	VerifyOTPSignUp(ctx context.Context, request *VerifyOTPRequest) (result *VerifyOTPResult, err error)
	VerifyOTPSignIn(ctx context.Context, request *VerifyOTPRequest) (result *VerifyOTPResult, err error)
	RemoveSession(ctx context.Context, session *Session) error
}

// VerifyOTPRequest is a request structure for OTP verification.
type VerifyOTPRequest struct {
	Code           string          `json:"code"`
	Platform       SessionPlatform `json:"platform"`
	ReferenceID    string          `json:"referenceID"`
	IdempotencyKey string          `json:"idempotencyKey"`
	IP             string
}

func (r *VerifyOTPRequest) Validate() error {
	result := &ValidationError{}
	codeLen := utf8.RuneCountInString(r.Code)
	referenceIDLen := utf8.RuneCountInString(r.ReferenceID)
	if codeLen < 4 || codeLen > 8 {
		AppendError(result, NewFieldError("code has invalid length", "code"))
	}
	if referenceIDLen == 0 || referenceIDLen > 255 {
		AppendError(result, NewFieldError("referenceID has invalid length", "referenceID"))
	}

	allowedPlatform := false
	for i := range platformAllowedList {
		if platformAllowedList[i] == r.Platform {
			allowedPlatform = true
			break
		}
	}
	if !allowedPlatform {
		AppendError(result, NewFieldError("provided platform is invalid", "platform"))
	}

	_, err := uuid.Parse(r.IdempotencyKey)
	if err != nil {
		AppendError(result, NewFieldError("provided idempotency key is not a valid uuid v4", "idempotencyKey"))
		result.InternalErrors = append(result.InternalErrors, err)
	}

	if len(result.FieldErrors) != 0 {
		return result
	}

	return nil
}

// VerifyOTPResult is a service result structure for OTP verification.
type VerifyOTPResult struct {
	SessionToken string `json:"sessionToken"`
	User         *User  `json:"user"`
}
