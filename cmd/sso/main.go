package main

import (
	"github.com/kxddry/sso-auth/internal/app"
	"github.com/kxddry/sso-auth/internal/config"
	"github.com/kxddry/sso-auth/internal/lib/logger"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// init config
	cfg := config.MustLoad()
	// init logger
	log := logger.SetupLogger(cfg.Env)
	log.Debug("debug messages are enabled")

	// init app
	application := app.New(log, cfg.GRPC.Port, cfg.Storage, cfg.TokenTTL, cfg.PrivkeyPath, cfg.PubkeyPath, cfg.KeyId)

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
