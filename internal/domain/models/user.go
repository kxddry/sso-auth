package models

type User struct {
	ID       int64
	Email    string
	Username string
	PassHash []byte
}
