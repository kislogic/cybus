package session

import (
	"context"
	"cybus/internal/dto"
	"cybus/internal/uow"
	"errors"
	"fmt"
	"strconv"
	"time"

	"sync"

	"go.uber.org/zap"
)

var t = time.Time{}

var sessionDeactivationPool sync.Pool

func acquireSessDeactivation() *dto.SessionDeactivation {
	v := sessionDeactivationPool.Get()
	if v == nil {
		return &dto.SessionDeactivation{}
	}
	return v.(*dto.SessionDeactivation)
}

func releaseSessDeactivation(d *dto.SessionDeactivation) {
	d.ID = 0
	d.IP = ""
	d.SessionID = 0
	d.CreatedAt = t
	sessionDeactivationPool.Put(d)
}

const (
	userSessionKeyPrefix = "userSessions#"
)

type sessionService struct {
	sessionStorage             dto.UserSessionStorage
	sessionDeactivationStorage dto.SessionDeactivationsStorage
	startUOW                   uow.StartUnitOfWork
	disabled                   *DisabledMethods
	timeouts                   *Timeouts
	cache                      dto.Cache
	logger                     *zap.Logger
}

type Timeouts struct {
	ListUserSessions  time.Duration
	DeactivateSession time.Duration
}

type DisabledMethods struct {
	ListUserSessions  bool
	DeactivateSession bool
}

// NewSessionService is a constructor-like function for dto.SessionService.
func NewSessionService(
	sessionStorage dto.UserSessionStorage,
	sessionDeactivationStorage dto.SessionDeactivationsStorage,
	startUOW uow.StartUnitOfWork,
	disabled *DisabledMethods,
	timeouts *Timeouts,
	cache dto.Cache,
	logger *zap.Logger) (dto.SessionService, error) {

	if sessionStorage == nil {
		return nil, errors.New("session service: provided user session storage is nil")
	}

	if sessionDeactivationStorage == nil {
		return nil, errors.New("session service: provided session deactivation storage is nil")
	}

	if startUOW == nil {
		return nil, errors.New("session service: provided uow to user session storage is nil")
	}

	if disabled == nil {
		return nil, errors.New("session service: provided disabled methods to session service is nil")
	}

	if timeouts == nil {
		return nil, errors.New("session service: provided timeouts to session service are nil")
	}

	if cache == nil {
		return nil, errors.New("session service: provided cache to session service is nil")
	}

	if logger == nil {
		return nil, errors.New("session service: provided logger to session service is nil")
	}

	return &sessionService{
		sessionStorage:             sessionStorage,
		sessionDeactivationStorage: sessionDeactivationStorage,
		startUOW:                   startUOW,
		disabled:                   disabled,
		timeouts:                   timeouts,
		cache:                      cache,
		logger:                     logger,
	}, nil
}

func (svc *sessionService) DeactivateSession(ctx context.Context, id string, user *dto.User, session *dto.Session, ip string) (bool, error) {

	if svc.disabled.DeactivateSession {
		return false, dto.ErrGeneralServiceDisabled
	}

	nctx, cancel := context.WithTimeout(ctx, svc.timeouts.DeactivateSession)
	defer cancel()

	sessionID, err := strconv.Atoi(id)
	if err != nil {
		ve := &dto.ValidationError{}
		ve.InternalErrors = append(ve.InternalErrors, err)
		dto.AppendError(ve, dto.NewFieldError("id is a not a valid session identifier", "id"))
		return false, ve
	}

	token, deactivated, err := svc.sessionStorage.GetSession(nctx, uint64(sessionID))
	if err != nil {
		return false, err
	}
	if deactivated {
		return false, dto.ErrSessionAlreadyDeactivated
	}

	mustLogout := false
	if token == session.Token {
		mustLogout = true
	}

	err = svc.startUOW(nctx, uow.Write, func(ctx context.Context, uw uow.UnitOfWork) error {

		if err := uw.UserSessions().SetDeactivated(ctx, uint64(sessionID)); err != nil {
			return err
		}

		sessDeactivation := acquireSessDeactivation()
		defer releaseSessDeactivation(sessDeactivation)

		sessDeactivation.CreatedAt = time.Now().UTC()
		sessDeactivation.SessionID = uint64(sessionID)
		sessDeactivation.IP = ip

		if err = uw.SessionDeactivations().StoreDeactivation(ctx, sessDeactivation); err != nil {
			return err
		}

		key := dto.Sessions + token
		if err := svc.cache.Del(ctx, key); err != nil {
			return fmt.Errorf("remove session from cache during session deactivation problem: %w", err)
		}

		key = userSessionKeyPrefix + fmt.Sprintf("%d", user.ID)
		if err := svc.cache.Del(ctx, key); err != nil {
			return fmt.Errorf("remove session list from cache during session deactivation problem: %w", err)
		}

		return nil

	}, svc.sessionStorage, svc.sessionDeactivationStorage)

	return mustLogout, nil

}

// ListUserSessions list 20 last sign ins / sign ups which created session.
// Used inside view when user can flush a suspisious session login.
func (svc *sessionService) ListUserSessions(ctx context.Context, user *dto.User) ([]*dto.UserSession, error) {

	if svc.disabled.ListUserSessions {
		return nil, dto.ErrGeneralServiceDisabled
	}

	nctx, cancel := context.WithTimeout(ctx, svc.timeouts.ListUserSessions)
	defer cancel()

	userSessions := make([]*dto.UserSession, 0, 20)
	key := userSessionKeyPrefix + fmt.Sprintf("%d", user.ID)
	if err := svc.cache.Get(nctx, key, &userSessions); err != nil {
		if !errors.Is(err, dto.ErrCacheMiss) {
			svc.logger.Error("list user sessions problem while retrieving from cache", zap.Uint64("userID", uint64(user.ID)), zap.Error(err))
		}
		userSessions, err = svc.sessionStorage.ListUserSessions(nctx, uint64(user.ID))
		if err != nil {
			return nil, err
		}
		if err := svc.cache.Set(nctx, key, userSessions, time.Duration(3)*time.Minute); err != nil {
			svc.logger.Error("list user sessions problem while setting to cache", zap.Error(err), zap.Uint64("userID", uint64(user.ID)))
		}
	}

	return userSessions, nil
}
