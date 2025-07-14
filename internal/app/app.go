package app

import (
	"github.com/kxddry/sso-auth/internal/app/grpcapp"
	"github.com/kxddry/sso-auth/internal/config"
	"github.com/kxddry/sso-auth/internal/services/auth"
	"github.com/kxddry/sso-auth/internal/storage/postgres"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

// New creates a new App instance
func New(log *slog.Logger, grpcPort int, storage config.Storage, tokenTTL time.Duration, privKeyPath, pubKeyPath, keyId string) *App {

	// init storage
	pq, err := postgres.New(storage)
	if err != nil {
		panic(err)
	}

	// init auth service
	authService, err := auth.New(log, pq, tokenTTL, privKeyPath, pubKeyPath, keyId)

	// init auth grpc server
	return &App{
		GRPCSrv: grpcapp.New(log, authService, grpcPort),
	}
}

func (a *App) Stop() {
	a.GRPCSrv.Stop()
	// close connection to postgres
}
