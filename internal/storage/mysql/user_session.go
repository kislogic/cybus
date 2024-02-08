package mysql

import (
	"context"
	"cybus/internal/dto"
	"database/sql"
	"errors"
	"fmt"
)

// userSessionStorage implements dto.UserSessionStorage via MySQL.
type userSessionStorage struct {
	db ExtendedDB
}

// NewUserSessionsStorage is a constructor-like function for dto.UserSessionStorage implemented via MySQL.
func NewUserSessionStorage(db ExtendedDB) (dto.UserSessionStorage, error) {
	if db == nil {
		return nil, errors.New("mysql: provided db handle to user session storage is nil")
	}
	return &userSessionStorage{db: db}, nil
}

// GetSessionToken retrieves session token by session id.
// Used to determine whether we need logout user on session deactivation.
func (s *userSessionStorage) GetSession(ctx context.Context, id uint64) (string, bool, error) {

	const query = `SELECT token, disabled FROM session WHERE id = ?`

	var (
		token       string
		deactivated bool
	)

	if err := s.db.QueryRowContext(ctx, query, id).Scan(&token, &deactivated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, dto.ErrSessionNotFound
		}
		return "", false, fmt.Errorf("user session storage: problem while get session by id: %w", err)
	}

	return token, deactivated, nil
}

func (s *userSessionStorage) SetDeactivated(ctx context.Context, id uint64) error {

	const query = `UPDATE session SET disabled = true WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("mysql: problem while set session disabled %d: %w", id, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql: rows.Affected problem while set session disabled %d: %w", id, err)
	}
	if affected != 1 {
		return dto.ErrSessionUpdateNotSuccessful
	}

	return nil
}

// ListUserSessions lists user sessions from persistent storage which user can view and disable.
func (s *userSessionStorage) ListUserSessions(ctx context.Context, userID uint64) ([]*dto.UserSession, error) {

	const query = `SELECT id, place, disabled, platform, created_at, ip FROM session WHERE user_id = ? ORDER BY id DESC LIMIT 20`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("user session storage: problem while making list sessions query: %w", err)
	}

	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	userSessions := make([]*dto.UserSession, 0, 20)

	for rows.Next() {

		var userSession = &dto.UserSession{}

		if err := rows.Scan(
			&userSession.ID,
			&userSession.Place,
			&userSession.Disabled,
			&userSession.SessionPlatform,
			&userSession.CreatedAt,
			&userSession.IP); err != nil {
			return nil, fmt.Errorf("user session storage: problem while scan user session: %w", err)
		}

		userSessions = append(userSessions, userSession)

	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user session storage: problem while calling rows.Err(): %w", err)
	}

	return userSessions, nil

}
