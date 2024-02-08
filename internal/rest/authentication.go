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
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type verifyOTPResponse struct {
	SessionToken string    `json:"sessionToken"`
	User         *dto.User `json:"user"`
	Success      bool      `json:"success"`
	Reason       string    `json:"reason,omitempty"`
}

type signInResponse signupResponse

type signupResponse struct {
	Success     bool   `json:"success"`
	PinLength   int    `json:"pinLength"`
	ReferenceID string `json:"referenceID"`
	Reason      string `json:"reason,omitempty"`
}

type removeSessionResponse struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason,omitempty"`
}

type authenticationBackend struct {
	authenticationService dto.AuthenticationService
	respond               *respond.Responder
	logger                *zap.Logger
}

// newAuthenticationBackend returns a new instance of authenticationBackend.
func newAuthenticationBackend(b *APIBackend) *authenticationBackend {
	return &authenticationBackend{
		authenticationService: b.AuthenticationService,
		respond:               b.Respond,
		logger:                b.Logger.With(zap.String("handler", "authentication")),
	}
}

type authenticationHandler struct {
	authenticationService dto.AuthenticationService
	respond               *respond.Responder
	logger                *zap.Logger

	requestCount *prometheus.CounterVec
}

func newAuthenticationHandler(b *authenticationBackend) *authenticationHandler {
	const (
		namespace = "dto"
		subsystem = "auth"
	)
	return &authenticationHandler{
		authenticationService: b.authenticationService,
		requestCount: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "requests_total",
			Help:      "Number of http requests received",
		}, []string{"method", "result"}),
		respond: b.respond,
		logger:  b.logger}
}

func (h *authenticationHandler) prometheusCollectors() []prometheus.Collector {
	return []prometheus.Collector{h.requestCount}
}

func (h *authenticationHandler) routes(nrapp *newrelic.Application, authenticationMiddleware *middleware.Authentication) chi.Router {

	r := chi.NewRouter()
	_, signInH := newrelic.WrapHandleFunc(nrapp, "/auth/signin", h.handleSignIn)
	_, signupH := newrelic.WrapHandleFunc(nrapp, "/auth/signup", h.handleSignUp)
	_, otpVerifyHSignUp := newrelic.WrapHandleFunc(nrapp, "/auth/signup/verify-otp", h.handleVerifyOTPSignUp)
	_, otpVerifyHSignIn := newrelic.WrapHandleFunc(nrapp, "/auth/signin/verify-otp", h.handleVerifyOTPSignIn)
	_, removeSessionH := newrelic.WrapHandleFunc(nrapp, "/auth/session/remove", h.handleRemoveSession)

	r.Post("/signup", signupH)
	r.Post("/signin", signInH)
	r.Post("/signup/verify-otp", otpVerifyHSignUp)
	r.Post("/signin/verify-otp", otpVerifyHSignIn)
	r.Route("/sessions", func(r chi.Router) {
		r.Use(authenticationMiddleware.Authenticate)
		r.Delete("/", removeSessionH)
	})

	return r
}

func (h *authenticationHandler) handleRemoveSession(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	session := getSession(ctx)

	err := h.authenticationService.RemoveSession(ctx, session)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return
		default:
			h.logger.Error("remove session: service problem while trying to remove session",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err))
			h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
			return
		}
	}

	h.respond.Ok(w, NewRESTResponse(&removeSessionResponse{Success: true}))

}

// handleSignIn requests verification code for subsequent sign in.
func (h *authenticationHandler) handleSignIn(w http.ResponseWriter, r *http.Request) {

	signInRequest := dto.SignInRequest{}
	if err := decode(r, &signInRequest); err != nil {
		h.logger.Error("sign in: problem while decoding body request", zap.String("ip", r.RemoteAddr), zap.Error(err))
		h.respond.BadRequest(w, NewRESTError(reasonDecoding, "problem while decoding input parameters"))
		return
	}
	signInRequest.IP = r.RemoteAddr

	res, err := h.authenticationService.SignIn(r.Context(), &signInRequest)
	if err != nil {
		var validationErr *dto.ValidationError
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.As(err, &validationErr):
			h.logger.Warn("sign in: validation problem occurred",
				zap.String("ip", r.RemoteAddr),
				zap.Errors("internal", validationErr.InternalErrors), zap.Error(err))
			h.respond.BadRequest(w, NewRESTValidationError(reasonValidation, "problem while validating request", validationErr))
			return
		case errors.Is(err, dto.ErrRateLimit):
			h.respond.TooManyRequests(w, NewRESTResponse(&signInResponse{Reason: "rateLimit", Success: false}))
			return
		case errors.Is(err, dto.ErrSignInDisabled):
			h.respond.Ok(w, NewRESTResponse(&signInResponse{Reason: "signinDisabled", Success: false}))
			return
		default:
			h.logger.Error("sign in: service problem while trying to login user via otp",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err))
			h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
			return
		}
	}

	h.respond.Ok(w, NewRESTResponse(&signInResponse{Success: true, PinLength: res.PinLength, ReferenceID: res.ReferenceID}))
}

// handleSignUp sends OTP code for verification after the first step of registration.
func (h *authenticationHandler) handleSignUp(w http.ResponseWriter, r *http.Request) {

	signupRequest := dto.SignUpRequest{}
	if err := decode(r, &signupRequest); err != nil {
		h.logger.Error("sign up: problem while decoding body request", zap.String("ip", r.RemoteAddr), zap.Error(err))
		h.respond.BadRequest(w, NewRESTError(reasonDecoding, "problem while decoding input parameters"))
		return
	}
	signupRequest.IP = r.RemoteAddr

	res, err := h.authenticationService.SignUp(r.Context(), &signupRequest)
	if err != nil {
		var validationErr *dto.ValidationError
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.As(err, &validationErr):
			h.logger.Warn("sign up: validation problem occurred",
				zap.String("ip", r.RemoteAddr),
				zap.Errors("internal", validationErr.InternalErrors), zap.Error(err))
			h.respond.BadRequest(w, NewRESTValidationError(reasonValidation, "problem while validating request", validationErr))
			return
		case errors.Is(err, dto.ErrRateLimit):
			h.respond.Ok(w, NewRESTResponse(&signupResponse{Reason: "rateLimit", Success: false}))
			return
		case errors.Is(err, dto.ErrSignupDisabled):
			h.respond.Ok(w, NewRESTResponse(&signupResponse{Reason: "signupDisabled", Success: false}))
			return
		default:
			h.logger.Error("sign up: service problem while trying to register new user",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err))
			h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
			return
		}
	}

	h.respond.Ok(w, NewRESTResponse(&signupResponse{Success: true, PinLength: res.PinLength, ReferenceID: res.ReferenceID}))
}

// handleVerifyOTPSignIn verifies code submitted by user after sign in.
func (h *authenticationHandler) handleVerifyOTPSignIn(w http.ResponseWriter, r *http.Request) {
	verifyOTPRequest := dto.VerifyOTPRequest{}
	if err := decode(r, &verifyOTPRequest); err != nil {
		h.logger.Error("verify otp sign in: problem while decoding body request", zap.String("ip", r.RemoteAddr), zap.Error(err))
		h.respond.BadRequest(w, NewRESTError(reasonDecoding, "problem while decoding input parameters"))
		return
	}
	verifyOTPRequest.IP = r.RemoteAddr
	res, err := h.authenticationService.VerifyOTPSignIn(r.Context(), &verifyOTPRequest)
	if err != nil {
		var validationErr *dto.ValidationError
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.Is(err, dto.ErrUserIsBanned):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: reasonBan, Success: false}))
			return
		case errors.Is(err, dto.ErrUserNotFound):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "badCode", Success: false}))
			return
		case errors.As(err, &validationErr):
			h.logger.Warn("verify otp sign in: validation problem occurred",
				zap.String("ip", r.RemoteAddr),
				zap.Errors("internal", validationErr.InternalErrors), zap.Error(err))
			h.respond.BadRequest(w, NewRESTValidationError(reasonValidation, "problem while validating request", validationErr))
			return
		case errors.Is(err, dto.ErrBadCode):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "badCode", Success: false}))
			return
		case errors.Is(err, dto.ErrCodeExpired):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "codeExpired", Success: false}))
			return
		case errors.Is(err, dto.ErrRateLimit):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "rateLimit", Success: false}))
			return
		case errors.Is(err, dto.ErrSignInDisabled):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "signinDisabled", Success: false}))
			return
		default:
			h.logger.Error("verify otp sign in: service problem while trying to register new user",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err))
			h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
			return
		}
	}

	h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{User: res.User, Success: true, SessionToken: res.SessionToken}))

}

// handleVerifyOTP verifies OTP sent to user after sign up, creates user in a database and returns valid tokens.
func (h *authenticationHandler) handleVerifyOTPSignUp(w http.ResponseWriter, r *http.Request) {
	verifyOTPRequest := dto.VerifyOTPRequest{}
	if err := decode(r, &verifyOTPRequest); err != nil {
		h.logger.Error("verify otp sign up: problem while decoding body request", zap.String("ip", r.RemoteAddr), zap.Error(err))
		h.respond.BadRequest(w, NewRESTError(reasonDecoding, "problem while decoding input parameters"))
		return
	}
	verifyOTPRequest.IP = r.RemoteAddr
	res, err := h.authenticationService.VerifyOTPSignUp(r.Context(), &verifyOTPRequest)
	if err != nil {
		var validationErr *dto.ValidationError
		switch {
		case errors.Is(err, context.Canceled):
			return
		case errors.As(err, &validationErr):
			h.logger.Warn("verify otp sign up: validation problem occurred",
				zap.String("ip", r.RemoteAddr),
				zap.Errors("internal", validationErr.InternalErrors), zap.Error(err))
			h.respond.BadRequest(w, NewRESTValidationError(reasonValidation, "problem while validating request", validationErr))
			return
		case errors.Is(err, dto.ErrBadCode):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "badCode", Success: false}))
			return
		case errors.Is(err, dto.ErrAskForSignIn):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "alreadySignedUp", Success: false}))
			return
		case errors.Is(err, dto.ErrCodeExpired):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "codeExpired", Success: false}))
			return
		case errors.Is(err, dto.ErrRateLimit):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "rateLimit", Success: false}))
			return
		case errors.Is(err, dto.ErrSignupDisabled):
			h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{Reason: "signupDisabled", Success: false}))
			return
		default:
			h.logger.Error("verify otp sign up: service problem while trying to register new user",
				zap.String("ip", r.RemoteAddr),
				zap.Error(err))
			h.respond.InternalServerError(w, NewRESTError(reasonInternalError, "unknown problem occurred"))
			return
		}
	}
	h.respond.Ok(w, NewRESTResponse(&verifyOTPResponse{User: res.User, Success: true, SessionToken: res.SessionToken}))
}
