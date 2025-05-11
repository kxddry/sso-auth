package app

import (
	"log/slog"
	"sso-auth/internal/app/grpcapp"
	"sso-auth/internal/config"
	"sso-auth/internal/services/auth"
	"sso-auth/internal/storage/postgres"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

// New creates a new App instance
func New(log *slog.Logger, grpcPort int, storage config.Storage, tokenTTL time.Duration) *App {

	// TODO: init storage
	pq, err := postgres.New(storage)
	if err != nil {
		panic(err)
	}

	// TODO: init auth service
	authService := auth.New(log, pq, tokenTTL)

	// TODO: init auth grpc server
	return &App{
		GRPCSrv: grpcapp.New(log, authService, grpcPort),
	}
}

func (a *App) Stop() {
	a.GRPCSrv.Stop()
	// close connection to postgres
}
