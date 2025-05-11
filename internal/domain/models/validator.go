package models

import "github.com/kxddry/sso-auth/internal/lib/validator"

const (
	Invalid  = validator.Fail
	Username = validator.Username
	Email    = validator.Email
)
