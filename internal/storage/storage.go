package storage

import "errors"

var (
	ErrUserExists      = errors.New("user already exists")
	ErrUserNotFound    = errors.New("user not found")
	ErrAppNotFound     = errors.New("app not found")
	ErrAppSecretExists = errors.New("app secret already exists")
	ErrWrongAppSecret  = errors.New("wrong app secret")
)
