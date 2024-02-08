package dto

import (
	"context"
	"errors"
	"strconv"
	"time"
)

type User struct {
	ID            UserID       `json:"id"`
	Avatar        string       `json:"avatar,omitempty"`
	Phone         string       `json:"phone,omitempty"`
	Email         string       `json:"email,omitempty"`
	FullName      string       `json:"fullName,omitempty"`
	PasswordHash  PasswordHash `json:"-"`
	IsDeactivated bool         `json:"-"`
	IsBanned      bool         `json:"-"`
	RequestLocale string       `json:"-"`
	CreatedAt     time.Time    `json:"-"`
	UpdatedAt     time.Time    `json:"-"`
}

func (u *User) Valid() error { return nil }

type PasswordHash = string

type UserStorage interface {
	GetUser(ctx context.Context, phone string) (*User, error)
	StoreUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	GetPassword(ctx context.Context, userID uint64) (string, error)
}

type UserID uint64

func (id UserID) Valid() error {
	if id == 0 {
		return errors.New("id is equal to zero")
	}
	return nil
}

func (id UserID) String() string {
	return strconv.FormatInt(int64(id), 10)
}
