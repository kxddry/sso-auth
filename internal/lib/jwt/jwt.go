package jwt

import (
	"crypto/ed25519"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kxddry/sso-auth/internal/domain/models"
	"strconv"
	"time"
)

func NewToken(user models.User, app models.App, privateKey *ed25519.PrivateKey, ttl time.Duration, keyId string) (string, error) {
	now := time.Now()

	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(user.ID, 10),
		Issuer:    "auth-service",
		Audience:  []string{app.Name},
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		IssuedAt:  jwt.NewNumericDate(now),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	token.Header["kid"] = keyId

	return token.SignedString(privateKey)
}
