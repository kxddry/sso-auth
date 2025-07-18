package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/kxddry/sso-auth/internal/domain/models"
	"github.com/kxddry/sso-auth/internal/lib/jwt"
	"github.com/kxddry/sso-auth/internal/lib/logger/sl"
	"github.com/kxddry/sso-auth/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(ctx context.Context, email, username string, hash []byte) (uid int64, err error)
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

// New returns a new instance of the Auth service.
func New(log *slog.Logger, storage Storage, tokenTTL time.Duration) *Auth {
	return &Auth{
		userSaver:    storage,
		userProvider: storage,
		log:          log,
		appProvider:  storage,
		tokenTTL:     tokenTTL,
	}
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
	token, err := jwt.NewToken(u, app, a.tokenTTL)
	if err != nil {
		log.Debug("failed to generate token", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return token, nil
}

// RegisterNewUser registers a new user when possible, returns an error when not.
func (a *Auth) RegisterNewUser(ctx context.Context, email string, username string, password string) (int64, error) {
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
	id, err := a.userSaver.SaveUser(ctx, email, username, hash)
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
		if errors.Is(err, storage.ErrAppSecretExists) {
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
