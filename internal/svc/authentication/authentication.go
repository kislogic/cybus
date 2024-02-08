package authentication

import (
	"context"
	"crypto/rand"
	"cybus/internal/dto"
	"cybus/internal/ipgeolocation"
	"cybus/internal/uow"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

const (
	codeSignUp = "codeSignUp:"
	codeSignIn = "codeSignIn:"
)

// authenticationService implements dto.AuthenticationService.
type authenticationService struct {
	userStorage    dto.UserStorage
	sessionStorage dto.SessionStorage
	startUOW       uow.StartUnitOfWork
	cache          dto.Cache
	verification   *Verification
	ipGeoClient    *ipgeolocation.GeoLocationClient
	logger         *zap.Logger

	signUpDisabled bool
	signInDisabled bool
}

// Verification is a supplementary structure for code verification.
type Verification struct {
	CompanyName string
	Verifier    dto.OTPVerifier
}

// NewAuthenticationService is a constructor-like function for service layer which contains authentication
// business-logic.
func NewAuthenticationService(
	userStorage dto.UserStorage,
	sessionStorage dto.SessionStorage,
	cache dto.Cache,
	startUOW uow.StartUnitOfWork,
	verification *Verification,
	ipGeoClient *ipgeolocation.GeoLocationClient,
	logger *zap.Logger) (dto.AuthenticationService, error) {

	if userStorage == nil {
		return nil, errors.New("authentication service: provided user storage is nil")
	}

	if sessionStorage == nil {
		return nil, errors.New("authentication service: provided session storage is nil")
	}

	if cache == nil {
		return nil, errors.New("authentication service: provided cache is nil")
	}
	if startUOW == nil {
		return nil, errors.New("authentication service: provided unit of work is nil")
	}
	if verification == nil {
		return nil, errors.New("authentication service: provided verify client is nil")
	}

	if ipGeoClient == nil {
		return nil, errors.New("authentication service: provided ip geolocation client is nil")
	}

	if logger == nil {
		return nil, errors.New("authentication service: provided logger is nil")
	}

	return &authenticationService{
		userStorage:    userStorage,
		sessionStorage: sessionStorage,
		startUOW:       startUOW,
		cache:          cache,
		verification:   verification,
		ipGeoClient:    ipGeoClient,
		logger:         logger}, nil
}

// awaitRL is a rate-limiter.
func (svc *authenticationService) awaitRL(ctx context.Context, prefix string, val string, dur time.Duration) error {

	key := prefix + val
	var cachedVal string
	if err := svc.cache.Get(ctx, key, &cachedVal); err != nil {
		if !errors.Is(err, dto.ErrCacheMiss) {
			return err
		}
	}

	if cachedVal != "" {
		return dto.ErrRateLimit
	}

	return svc.cache.Set(ctx, key, val, dur)

}

func (svc *authenticationService) SignIn(ctx context.Context, r *dto.SignInRequest) (*dto.SignInResult, error) {

	if svc.signInDisabled {
		return nil, dto.ErrSignInDisabled
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	type previousSignInAttempt struct {
		Request *dto.SignInRequest `json:"request"`
		Result  *dto.SignInResult  `json:"result"`
	}

	key := "signInIdempotency#" + r.IdempotencyKey
	previousAttempt := &previousSignInAttempt{}
	if err := svc.cache.Get(ctx, key, previousAttempt); err != nil {
		if !errors.Is(err, dto.ErrCacheMiss) {
			return nil, err
		}
	}
	if previousAttempt.Request != nil && previousAttempt.Request.Phone == r.Phone {
		return previousAttempt.Result, nil
	}

	if err := svc.awaitRL(ctx, "signin_ip", r.IP, time.Second*20); err != nil {
		return nil, err
	}

	phone := fmt.Sprintf("%d%d", *r.ParsedPhone.CountryCode, *r.ParsedPhone.NationalNumber)

	resp, err := svc.verification.Verifier.RequestOTP(ctx, phone, svc.verification.CompanyName)
	if err != nil {
		return nil, err
	}

	if err := svc.cache.Set(ctx, codeSignIn+resp.ReferenceID, phone, time.Duration(dto.PinExpiry)*time.Second); err != nil {
		return nil, err
	}

	result := &dto.SignInResult{ReferenceID: resp.ReferenceID, PinLength: resp.PinLength}
	previousAttempt = &previousSignInAttempt{
		Request: r,
		Result:  result,
	}

	if err := svc.cache.Set(ctx, key, previousAttempt, time.Minute*1); err != nil {
		return nil, err
	}

	return result, nil

}

// SignUp sends otp code, saving passed user in a temporary memory cache.
func (svc *authenticationService) SignUp(ctx context.Context, r *dto.SignUpRequest) (*dto.SignUpResult, error) {

	if svc.signUpDisabled {
		return nil, dto.ErrSignupDisabled
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	type previousSignUpAttempt struct {
		Request *dto.SignUpRequest `json:"request"`
		Result  *dto.SignUpResult  `json:"result"`
	}

	key := "signUpIdempotency#" + r.IdempotencyKey
	previousAttempt := &previousSignUpAttempt{}
	if err := svc.cache.Get(ctx, key, previousAttempt); err != nil {
		if !errors.Is(err, dto.ErrCacheMiss) {
			return nil, err
		}
	}
	if previousAttempt.Request != nil && sameSignUpRequest(r, previousAttempt.Request) {
		return previousAttempt.Result, nil
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(r.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("signup: problem while generating password hash: %w", err)
	}

	if err := svc.awaitRL(ctx, "signup_ip", r.IP, time.Second*20); err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	user := &dto.User{
		CreatedAt:    now,
		UpdatedAt:    now,
		Email:        r.Email,
		FullName:     r.FullName,
		PasswordHash: dto.PasswordHash(passwordHash),
		Phone:        strconv.FormatUint(*r.ParsedPhone.NationalNumber, 10),
	}

	resp, err := svc.verification.Verifier.RequestOTP(ctx, user.Phone, svc.verification.CompanyName)
	if err != nil {
		return nil, err
	}

	if err := svc.cache.Set(ctx, codeSignUp+resp.ReferenceID, user, time.Duration(60)*time.Second); err != nil {
		return nil, err
	}

	result := &dto.SignUpResult{ReferenceID: resp.ReferenceID, PinLength: resp.PinLength}
	previousAttempt = &previousSignUpAttempt{
		Request: r,
		Result:  result,
	}

	if err := svc.cache.Set(ctx, key, previousAttempt, time.Minute*1); err != nil {
		return nil, err
	}

	return result, nil
}

// updateSessionGeoByIP updates place (country and city) from which user entered app and thus created a session
// uses external api to map ip to country and city.
func (svc *authenticationService) updateSessionGeoByIP(session *dto.Session) {

	opCtx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	res, err := svc.ipGeoClient.GetIPGeo(opCtx, session.IP)
	if err != nil {
		svc.logger.Error("geo location by ip problem per session",
			zap.String("ip", session.IP),
			zap.Error(err),
			zap.Uint64("userID", uint64(session.User.ID)))
		return
	}

	if res.City != "" && res.CountryName != "" {
		if err := svc.sessionStorage.UpdatePlace(opCtx, session.ID, res.City+", "+res.CountryName); err != nil {
			svc.logger.Error("geo location update session place problem", zap.Error(err),
				zap.Uint64("userID", uint64(session.User.ID)), zap.String("ip", session.IP))
		}
	}

}

func (svc *authenticationService) VerifyOTPSignIn(ctx context.Context, r *dto.VerifyOTPRequest) (*dto.VerifyOTPResult, error) {

	if svc.signInDisabled {
		return nil, dto.ErrSignInDisabled
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	type previousVerifyAttempt struct {
		Request *dto.VerifyOTPRequest `json:"request"`
		Result  *dto.VerifyOTPResult  `json:"result"`
	}

	key := "verifySignInIdempotency#" + r.IdempotencyKey
	previousAttempt := &previousVerifyAttempt{}
	if err := svc.cache.Get(ctx, key, previousAttempt); err != nil {
		if !errors.Is(err, dto.ErrCacheMiss) {
			return nil, err
		}
	}
	if previousAttempt.Request != nil && sameVerifyOTPRequest(r, previousAttempt.Request) {
		return previousAttempt.Result, nil
	}

	var phone string
	if err := svc.cache.Get(ctx, codeSignIn+r.ReferenceID, &phone); err != nil {
		if errors.Is(err, dto.ErrCacheMiss) {
			return nil, dto.ErrCodeExpired
		}
		return nil, err
	}

	if err := svc.verification.Verifier.VerifyOTP(ctx, r.ReferenceID, r.Code); err != nil {
		return nil, err
	}

	// todo: check that user agent is new, ask for password in such a case
	user, err := svc.userStorage.GetUser(ctx, phone[1:])
	if err != nil {
		return nil, err
	}

	if user.IsBanned {
		return nil, dto.ErrUserIsBanned
	}

	sessionToken, err := randomToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	session := dto.Session{
		CreatedAt:       now,
		IP:              r.IP,
		SessionPlatform: r.Platform,
		Token:           sessionToken,
		User:            user,
	}

	if err := svc.sessionStorage.StoreSession(ctx, &session); err != nil {
		return nil, err
	}

	if err := svc.cache.Set(ctx, dto.Sessions+sessionToken, &session, 0); err != nil {
		return nil, err
	}

	go svc.updateSessionGeoByIP(&session)
	go svc.flushSessionCache(uint64(user.ID))

	result := &dto.VerifyOTPResult{User: user, SessionToken: sessionToken}
	previousAttempt = &previousVerifyAttempt{
		Request: r,
		Result:  result,
	}

	if err := svc.cache.Set(ctx, key, previousAttempt, time.Minute*1); err != nil {
		return nil, err
	}

	return result, nil

}

func sameVerifyOTPRequest(request, prevRequest *dto.VerifyOTPRequest) bool {
	return request.Code == prevRequest.Code && request.ReferenceID == prevRequest.ReferenceID &&
		request.Platform == prevRequest.Platform && request.IdempotencyKey == prevRequest.IdempotencyKey
}

func sameSignUpRequest(request, prevRequest *dto.SignUpRequest) bool {
	return request.Email == prevRequest.Email &&
		request.FullName == prevRequest.FullName &&
		request.IdempotencyKey == prevRequest.IdempotencyKey &&
		request.Phone == prevRequest.Phone &&
		request.Password == prevRequest.Password
}

// flushSessionCache flushes cached sessions where user can view his sessions.
// It does it because on sign in new session is added to the list of potentially cached sessions.
func (svc *authenticationService) flushSessionCache(userID uint64) {

	const userSessionKeyPrefix = "userSessions#"

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*300)
	defer cancel()

	key := userSessionKeyPrefix + fmt.Sprintf("%d", userID)
	if err := svc.cache.Del(ctx, key); err != nil {
		svc.logger.Error("remove session list from cache during sign in problem", zap.Error(err), zap.Uint64("userID", userID))
	}
}

// VerifyOTPSignUp verifies OTP sent to user after sign up.
// It OTP is correct, creates user and returns tokens for authentication.
func (svc *authenticationService) VerifyOTPSignUp(ctx context.Context, r *dto.VerifyOTPRequest) (*dto.VerifyOTPResult, error) {

	if svc.signUpDisabled {
		return nil, dto.ErrSignupDisabled
	}

	if err := r.Validate(); err != nil {
		return nil, err
	}

	type previousVerifyAttempt struct {
		Request *dto.VerifyOTPRequest `json:"request"`
		Result  *dto.VerifyOTPResult  `json:"result"`
	}

	key := "verifySignUpIdempotency#" + r.IdempotencyKey
	previousAttempt := &previousVerifyAttempt{}
	if err := svc.cache.Get(ctx, key, previousAttempt); err != nil {
		if !errors.Is(err, dto.ErrCacheMiss) {
			return nil, err
		}
	}
	if previousAttempt.Request != nil && sameVerifyOTPRequest(r, previousAttempt.Request) {
		return previousAttempt.Result, nil
	}

	var user dto.User
	if err := svc.cache.Get(ctx, codeSignUp+r.ReferenceID, &user); err != nil {
		if errors.Is(err, dto.ErrCacheMiss) {
			return nil, dto.ErrCodeExpired
		}
		return nil, err
	}

	if err := svc.verification.Verifier.VerifyOTP(ctx, r.ReferenceID, r.Code); err != nil {
		return nil, err
	}

	duplicateUser, err := svc.userStorage.GetUser(ctx, user.Phone)
	if err != nil {
		switch {
		case errors.Is(err, dto.ErrUserNotFound):
		default:
			return nil, err
		}
	}
	if duplicateUser != nil {
		return nil, dto.ErrAskForSignIn
	}

	if err := svc.cache.Del(ctx, codeSignUp+r.ReferenceID); err != nil {
		if !errors.Is(err, dto.ErrCacheMiss) {
			return nil, err
		}
	}

	sessionToken, err := randomToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	session := dto.Session{
		CreatedAt:       now,
		SessionPlatform: r.Platform,
		IP:              r.IP,
		Token:           sessionToken,
		User:            &user,
	}

	user.CreatedAt = now
	user.UpdatedAt = now

	err = svc.startUOW(ctx, uow.Write, func(ctx context.Context, uw uow.UnitOfWork) error {
		if err := uw.Users().StoreUser(ctx, &user); err != nil {
			return err
		}
		return uw.Sessions().StoreSession(ctx, &session)
	}, svc.sessionStorage, svc.userStorage)
	if err != nil {
		return nil, err
	}

	if err := svc.cache.Set(ctx, dto.Sessions+sessionToken, &session, 0); err != nil {
		return nil, err
	}

	result := &dto.VerifyOTPResult{User: &user, SessionToken: sessionToken}
	previousAttempt = &previousVerifyAttempt{
		Request: r,
		Result:  result,
	}
	if err := svc.cache.Set(ctx, key, previousAttempt, time.Minute*1); err != nil {
		return nil, err
	}

	go svc.updateSessionGeoByIP(&session)

	return result, nil
}

// RemoveSession permanently removes session from persistent server storage and session cache, making it unusable for next request.
// Used on logout.
func (svc *authenticationService) RemoveSession(ctx context.Context, session *dto.Session) error {
	key := dto.Sessions + session.Token
	if err := svc.cache.Del(ctx, key); err != nil {
		return err
	}
	return svc.sessionStorage.DeleteSession(ctx, session.Token)
}

// randomToken generates a 16-byte crypto random token and applies hex encoding to it.
func randomToken() (string, error) {
	b := [16]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		return "", fmt.Errorf("could not successfully read from the system CSPRNG: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
