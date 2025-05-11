package main

import (
	"os"
	"os/signal"
	"sso-auth/internal/app"
	"sso-auth/internal/config"
	"sso-auth/internal/lib/logger"
	"syscall"
)

func main() {
	// init config
	cfg := config.MustLoad()
	// init logger
	log := logger.SetupLogger(cfg.Env)
	log.Debug("debug messages are enabled")

	// init app
	application := app.New(log, cfg.GRPC.Port, cfg.Storage, cfg.TokenTTL)

	// run gRPC server
	go application.GRPCSrv.MustRun() // run gRPC server in a separate goroutine to avoid blocking

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop // wait for signal
	log.Info("received shutdown signal, stopping application")
	application.Stop() // stop gRPC server and database
	log.Info("gRPC server stopped")
	log.Info("application stopped")
}
