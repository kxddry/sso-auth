package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso-auth/internal/domain/models"
	"sso-auth/internal/lib/jwt"
	"sso-auth/internal/lib/logger/sl"
	"sso-auth/internal/storage"
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
	UserByEmail(ctx context.Context, email string) (models.User, error)
	UserByUsername(ctx context.Context, username string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int64) (models.App, error)
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
	ErrInvalidPlaceholder = errors.New("invalid email or username")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
)

// Login checks if the user with given credentials exists in the system.
// If the user exists and the password is correct, returns token.
// If the user exists, but password is incorrect, returns error.
// If the user doesn't exist, also returns error.
func (a *Auth) Login(ctx context.Context, placeholder string, typeOfPlaceholder int, password string, appID int64) (string, error) {
	const op = "services.auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("placeholder", placeholder),
	)

	var u models.User
	var err error
	switch typeOfPlaceholder {
	case models.Invalid:
		log.Debug("invalid placeholder")

		return "", fmt.Errorf("%s: %w", op, ErrInvalidPlaceholder)
	case models.Username:
		u, err = a.userProvider.UserByUsername(ctx, placeholder)
	case models.Email:
		u, err = a.userProvider.UserByEmail(ctx, placeholder)
	default:
		log.Debug("default")

		return "", fmt.Errorf("%s: %w", op, ErrInvalidPlaceholder)
	}
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
