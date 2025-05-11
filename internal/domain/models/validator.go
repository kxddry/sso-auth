package models

import "sso-auth/internal/lib/validator"

const (
	Invalid  = validator.Fail
	Username = validator.Username
	Email    = validator.Email
)
