package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/kxddry/sso-auth/internal/config"
	"github.com/kxddry/sso-auth/internal/domain/models"
	"github.com/kxddry/sso-auth/internal/lib/pqlinks"
	"github.com/kxddry/sso-auth/internal/storage"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type Storage struct {
	db *sql.DB
}

func (s *Storage) SaveUser(ctx context.Context, email, username string, hash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer tx.Rollback()

	var id int64
	query := `INSERT INTO users(email, username, pass_hash) VALUES ($1, $2, $3) RETURNING id;`
	err = tx.QueryRowContext(ctx, query, email, username, hash).Scan(&id)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" { // constraint unique violation
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, tx.Commit()
}

func (s *Storage) UserByEmail(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgres.UserByEmail"
	query := `SELECT * FROM users WHERE email = $1;`

	row := s.db.QueryRowContext(ctx, query, email)

	var u models.User
	err := row.Scan(&u.ID, &u.Email, &u.Username, &u.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return u, nil
}

func (s *Storage) UserByUsername(ctx context.Context, username string) (models.User, error) {
	const op = "storage.postgres.UserByUsername"
	query := `SELECT * FROM users WHERE username = $1;`

	row := s.db.QueryRowContext(ctx, query, username)
	var u models.User
	err := row.Scan(&u.ID, &u.Email, &u.Username, &u.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	return u, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	query := `SELECT * FROM admins WHERE user_id = $1;`
	row := s.db.QueryRowContext(ctx, query, userID)

	var res bool
	err := row.Scan(&res)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// check in the users table to see if this user even exists
			row := s.db.QueryRowContext(ctx, `SELECT * FROM users WHERE id = $1;`, userID)

			if err := row.Scan(&res); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return false, storage.ErrUserNotFound
				}
			}
			// if the user does exist, but he's not in the admin's table, he's not an admin
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return res, nil
}

func (s *Storage) App(ctx context.Context, appID int64) (models.App, error) {
	const op = "storage.postgres.App"

	row := s.db.QueryRowContext(ctx, `SELECT id, name, secret FROM apps WHERE id = $1`, appID)
	var app models.App
	err := row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, storage.ErrAppNotFound
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	return app, nil
}

func (s *Storage) AppID(ctx context.Context, appName, appSecret string) (int64, error) {
	const op = "storage.postgres.App"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer tx.Rollback()

	query := `SELECT id, secret FROM apps WHERE name = $1`
	row := tx.QueryRowContext(ctx, query, appName)
	var (
		appID  int64
		secret string
	)
	err = row.Scan(&appID, &secret)
	if err == nil {
		if secret != appSecret {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrWrongAppSecret)
		}
		return appID, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		query = `INSERT INTO apps (name, secret) VALUES ($1, $2) RETURNING id;`
		err = tx.QueryRowContext(ctx, query, appName, appSecret).Scan(&appID)
		if err != nil {
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
				return 0, fmt.Errorf("%s: %w", op, storage.ErrAppSecretExists)
			}
			return 0, fmt.Errorf("%s: %w", op, err)
		}

		return appID, tx.Commit()
	}

	return 0, fmt.Errorf("%s: %w", op, err)
}

func New(cfg config.Storage) (*Storage, error) {
	const op = "storage.postgres.New"
	dsn := pqlinks.DataSourceName(cfg)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &Storage{db: db}, db.Ping()
}
