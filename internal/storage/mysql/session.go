package mysql

import (
	"context"
	"cybus/internal/dto"
	"database/sql"
	"errors"
	"fmt"
)

type sessionStorage struct {
	db ExtendedDB
}

func NewSessionStorage(db ExtendedDB) (dto.SessionStorage, error) {
	if db == nil {
		return nil, errors.New("mysql: provided db handle to session storage is nil")
	}
	return &sessionStorage{db: db}, nil
}

// UpdatePlace updates city and country name from which user created session based on his ip address.
func (s *sessionStorage) UpdatePlace(ctx context.Context, id uint64, place string) error {

	const query = `UPDATE session SET place = ? WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query, place, id)
	if err != nil {
		return fmt.Errorf("mysql: problem while trying to update session place: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql: problem while calling res.RowsAffected while updating session place: %w", err)
	}

	if count != 1 {
		return fmt.Errorf("mysql: update session place count is bad: %d", count)
	}

	return nil

}

func (s *sessionStorage) StoreSession(ctx context.Context, sess *dto.Session) error {

	const query = `INSERT INTO session(token,created_at,ip,user_id,platform) VALUES (?,?,?,?,?)`

	res, err := s.db.ExecContext(ctx, query, sess.Token, sess.CreatedAt, sess.IP, sess.User.ID, sess.SessionPlatform)
	if err != nil {
		return fmt.Errorf("mysql: problem while trying to insert new session: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql: problem while calling res.RowsAffected while creating new session: %w", err)
	}

	if count != 1 {
		return fmt.Errorf("mysql: inserted session count is bad: %d", count)
	}

	lastInsertID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("mysql: problem while calling res.LastInsertId while creating new session: %w", err)
	}
	sess.ID = uint64(lastInsertID)

	return nil
}

func (s *sessionStorage) DeleteSession(ctx context.Context, token string) error {
	const query = `DELETE FROM session WHERE token = ?`
	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("mysql: problem while trying to delete session: %w", err)
	}
	return nil
}

func (s *sessionStorage) GetSession(ctx context.Context, sessionToken string) (*dto.Session, error) {

	const query = `SELECT s.token, s.created_at, s.ip, s.disabled,
                   u.id, u.email, u.phone, u.full_name, u.avatar, u.is_banned
                   FROM session AS s
                   JOIN user AS u ON  u.id = s.user_id WHERE token = ?`

	session, user := dto.Session{}, dto.User{}
	err := s.db.QueryRowContext(ctx, query, sessionToken).
		Scan(&session.Token, &session.CreatedAt, &session.IP, &session.Disabled,
			&user.ID, &user.Email, &user.Phone, &user.FullName, &user.Avatar, &user.IsBanned)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, dto.ErrSessionNotFound
		}
		return nil, fmt.Errorf("mysql: session not found in database by token: %w", err)
	}

	session.User = &user

	return &session, nil

}
