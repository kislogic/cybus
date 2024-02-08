package mysql

import (
	"context"
	"cybus/internal/dto"
	"errors"
	"fmt"
)

// sessionDeactivationStorage implements dto.SessionDeactivationStorage via MySQL.
type sessionDeactivationStorage struct {
	db ExtendedDB
}

// NewSessionDeactivationStorage is a constructor-like function for dto.SessionDeactivationStorage implemented via MySQL.
func NewSessionDeactivationStorage(db ExtendedDB) (dto.SessionDeactivationsStorage, error) {
	if db == nil {
		return nil, errors.New("mysql: provided db handle to user session storage is nil")
	}
	return &sessionDeactivationStorage{db: db}, nil
}

// StoreDeactivation stores new session deactivation for audit purposes.
func (s *sessionDeactivationStorage) StoreDeactivation(ctx context.Context, d *dto.SessionDeactivation) error {

	const query = `INSERT INTO session_deactivation (created_at, session_id, ip) VALUES (?, ?, ?)`

	res, err := s.db.ExecContext(ctx, query, d.CreatedAt, d.SessionID, d.IP)
	if err != nil {
		return fmt.Errorf("mysql: problem inserting session deactivation, session id %d: %w", d.SessionID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql: rows.Affected problem while store session deactivation, session id %d: %w", d.SessionID, err)
	}
	if affected != 1 {
		return errors.New("mysql: session deactivation result is 0")
	}

	return nil
}
