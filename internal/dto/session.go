package dto

import (
	"context"
	"errors"
	"time"
)

var (
	ErrSessionAlreadyDeactivated  = errors.New("session was deactivated previously")
	ErrSessionUpdateNotSuccessful = errors.New("session update 0 rows")
)

type UserSession struct {
	ID              uint64          `json:"id"`
	Place           *string         `json:"place"`
	Disabled        bool            `json:"disabled"`
	SessionPlatform SessionPlatform `json:"platform"`
	CreatedAt       time.Time       `json:"createdAt"`
	IP              string          `json:"ip"`
}

// SessionService abstracts management of sessions from user perspective
// where he can view active sessions and deactivate them.
type SessionService interface {
	// ListUserSessions lists last 20 user sessions among with device, place, ip address, time and date of login.
	// Used inside view when he/she can deactivate session.
	ListUserSessions(ctx context.Context, user *User) ([]*UserSession, error)
	// DeactivateSession  is called from view when user can list active sessions. Returns mustLogout true
	// when current user session is a session he/she wants to deactivate.
	DeactivateSession(ctx context.Context, id string, user *User, session *Session, ip string) (mustLogout bool, err error)
}

type SessionDeactivation struct {
	ID        uint64    `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	SessionID uint64    `json:"sessionID"`
	IP        string    `json:"ip"`
}

type SessionDeactivationsStorage interface {
	StoreDeactivation(ctx context.Context, deactivation *SessionDeactivation) error
}

// UserSessionStorage is used as a persistence layer for SessionService.
type UserSessionStorage interface {
	// ListUserSessions lists last 20 user sessions from the persistent storage ordered by id from the most recent.
	ListUserSessions(ctx context.Context, userID uint64) ([]*UserSession, error)
	// GetSession retrieves session token among with deactivation flag from the persistent storage by internal unique identifier.
	GetSession(ctx context.Context, sessionID uint64) (token string, deactivated bool, err error)
	// SetDeactivated sets deactivated flag for session.
	SetDeactivated(ctx context.Context, sessionID uint64) error
}

type SessionStorage interface {
	StoreSession(ctx context.Context, session *Session) error
	UpdatePlace(ctx context.Context, id uint64, place string) error
	GetSession(ctx context.Context, sessionToken string) (*Session, error)
	DeleteSession(ctx context.Context, token string) error
}

type SessionPlatform string

const (
	SessionPlatformAndroid SessionPlatform = "Android"
	SessionPlatformIOS     SessionPlatform = "iOS"
)

var platformAllowedList = []SessionPlatform{SessionPlatformAndroid, SessionPlatformIOS}

type Session struct {
	ID              uint64          `json:"id"`
	Place           *string         `json:"place"`
	Disabled        bool            `json:"disabled"`
	SessionPlatform SessionPlatform `json:"platform"`
	CreatedAt       time.Time       `json:"createdAt"`
	IP              string          `json:"ip"`
	Token           string          `json:"sessionToken"`
	User            *User           `json:"user"`
}
