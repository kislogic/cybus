package mysql

import (
	"context"
	"cybus/internal/dto"
	"database/sql"
	"errors"
	"fmt"
)

type userStorage struct {
	db ExtendedDB
}

func NewUserStorage(db ExtendedDB) (dto.UserStorage, error) {
	if db == nil {
		return nil, errors.New("mysql: provided db pool is nil")
	}
	return &userStorage{db: db}, nil
}

func (s *userStorage) StoreUser(ctx context.Context, u *dto.User) error {

	const query = `INSERT INTO user(created_at,updated_at,email,phone,full_name,password_hash,avatar) VALUES(?,?,?,?,?,?,?)`
	res, err := s.db.ExecContext(ctx, query, u.CreatedAt, u.UpdatedAt, u.Email, u.Phone, u.FullName, u.PasswordHash, u.Avatar)
	if err != nil {
		return fmt.Errorf("mysql: problem while trying to insert new user: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql: problem while calling res.RowsAffected while creating new user: %w", err)
	}

	if count != 1 {
		return fmt.Errorf("mysql: inserted user count is bad: %d", count)
	}

	lastInsertID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("mysql: problem while calling res.LastInsertId while creating new user: %w", err)
	}

	u.ID = dto.UserID(lastInsertID)

	return nil
}

func (s *userStorage) UpdateUser(ctx context.Context, u *dto.User) error {

	const query = `UPDATE user SET email = ?, phone = ?, 
					full_name = ?, password_hash = ?, avatar = ?, 
					updated_at = NOW() WHERE id = ?`

	res, err := s.db.ExecContext(ctx, query, u.Email, u.Phone, u.FullName, u.PasswordHash, u.Avatar, u.ID)
	if err != nil {
		return fmt.Errorf("mysql: problem while trying to update user: %w", err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("mysql: problem while calling res.RowsAffected while update user: %w", err)
	}

	if count != 1 {
		return fmt.Errorf("mysql: updated user count is bad: %d", count)
	}

	return nil
}

func (s *userStorage) GetUser(ctx context.Context, phone string) (*dto.User, error) {
	const query = `SELECT id, updated_at, email, phone, full_name, avatar FROM user WHERE phone = ?`
	u := &dto.User{}
	err := s.db.QueryRowContext(ctx, query, phone).Scan(&u.ID, &u.UpdatedAt, &u.Email, &u.Phone, &u.FullName, &u.Avatar)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, dto.ErrUserNotFound
		}
		return nil, fmt.Errorf("mysql: user not found in database by phone: %w", err)
	}
	return u, nil
}

func (s *userStorage) GetPassword(ctx context.Context, userID uint64) (string, error) {

	const query = `SELECT password_hash FROM user WHERE id = ?`

	var passwordHash string
	if err := s.db.QueryRowContext(ctx, query, userID).Scan(&passwordHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", dto.ErrUserNotFound
		}
		return "", fmt.Errorf("mysql: user storage, problem on get password hash: %w", err)
	}

	return passwordHash, nil
}
