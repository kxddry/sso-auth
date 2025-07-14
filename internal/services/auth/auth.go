package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/kxddry/sso-auth/internal/domain/models"
	"github.com/kxddry/sso-auth/internal/lib/jwt"
	"github.com/kxddry/sso-auth/internal/lib/logger/sl"
	"github.com/kxddry/sso-auth/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"os"
	"time"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
	pubkey       *ed25519.PublicKey
	privateKey   *ed25519.PrivateKey
	KeyID        string
}

type UserSaver interface {
	Save(ctx context.Context, email string, hash []byte) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int64) (models.App, error)
	AppID(ctx context.Context, appName, appSecret string) (int64, error) // generates an app ID
}

type Storage interface {
	UserSaver
	UserProvider
	AppProvider
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	edPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Not an Ed25519 Private Key")
	}
	return edPriv, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("Not an Ed25519 Public Key")
	}
	return edPub, nil
}

// New returns a new instance of the Auth service.
func New(log *slog.Logger, storage Storage, tokenTTL time.Duration, privateKeyPath, publicKeyPath string, keyId string) (*Auth, error) {

	pubKey, err := loadPublicKey(privateKeyPath)
	if err != nil {
		return nil, err
	}

	privKey, err := loadPrivateKey(publicKeyPath)
	if err != nil {
		return nil, err
	}

	return &Auth{
		log:          log,
		userSaver:    storage,
		userProvider: storage,
		appProvider:  storage,
		tokenTTL:     tokenTTL,
		pubkey:       &pubKey,
		privateKey:   &privKey,
		KeyID:        keyId,
	}, nil
}

var (
	ErrInvalidCredentials = errors.New("invalid login or password")
	ErrInvalidEmail       = errors.New("invalid email")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrAppSecretExists    = errors.New("app secret already exists")
	ErrWrongAppSecret     = errors.New("wrong app secret")
)

// Login checks if the user with given credentials exists in the system.
// If the user exists and the password is correct, returns token.
// If the user exists, but password is incorrect, returns error.
// If the user doesn't exist, also returns error.
func (a *Auth) Login(ctx context.Context, email string, password string, appID int64) (string, error) {
	const op = "services.auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	u, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		log.Error("failed to get user", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err = bcrypt.CompareHashAndPassword(u.PassHash, []byte(password)); err != nil {
		log.Info(ErrInvalidCredentials.Error(), sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Debug("failed to get app", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")
	token, err := jwt.NewToken(u, app, a.privateKey, a.tokenTTL, a.KeyID)
	if err != nil {
		log.Debug("failed to generate token", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return token, nil
}

// RegisterNewUser registers a new user when possible, returns an error when not.
func (a *Auth) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	id, err := a.userSaver.Save(ctx, email, hash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))

			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}

		log.Error("failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return id, nil
}

// IsAdmin checks whether the user with userID is an admin.
func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "Auth.IsAdmin"
	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return false, ErrUserNotFound
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("checked if user is admin", slog.Bool("isAdmin", isAdmin))
	return isAdmin, nil
}

func (a *Auth) AppID(ctx context.Context, name, secret string) (int64, error) {
	const op = "auth.AppID"

	log := a.log.With(
		slog.String("op", op),
		slog.String("appName", name),
	)

	log.Info("generating appId")

	appId, err := a.appProvider.AppID(ctx, name, secret)
	if err != nil {
		if errors.Is(err, storage.ErrAppPublicKeyExists) {
			log.Warn("app secret already exists", sl.Err(err))
			return 0, fmt.Errorf("%s: %w", op, ErrAppSecretExists)
		}
		if errors.Is(err, storage.ErrWrongAppSecret) {
			log.Warn("wrong app secret", sl.Err(err))
			return 0, fmt.Errorf("%s: %w", op, ErrWrongAppSecret)
		}
		log.Error("error getting appID", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("generated or fetched appID", slog.Int64("appId", appId))
	return appId, nil
}

func (a *Auth) GetPublicKey() models.PubkeyResponse {
	pemStr, err := encodeEd25519PublicKeyPEM(a.pubkey)
	if err != nil {
		a.log.Error("failed to encode public key", sl.Err(err))
		return models.PubkeyResponse{}
	}

	return models.PubkeyResponse{
		Pubkey:    pemStr,
		Algorithm: "EdDSA",
		KeyId:     a.KeyID,
	}
}

func encodeEd25519PublicKeyPEM(pub *ed25519.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return buf.String(), err
}
