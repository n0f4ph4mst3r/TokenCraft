package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/n0f4ph4mst3r/TokenCraft/internal/app"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/config"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()
	fmt.Printf("Config loaded: %+v\n", cfg)

	log := setupLogger(cfg.Env)

	log.Info("Starting application...", slog.String("env", cfg.Env))
	log.Debug("Debugging is enabled")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	_app := app.New(
		ctx,
		log,
		cfg.GRPC.Port,
		cfg.DatabaseURL,
		&cfg.Cache,
		cfg.JwtTTL,
		cfg.TokenTTL,
		cfg.Secret,
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- _app.GRPC.Run()
	}()

	select {
	case <-ctx.Done():
		log.Info("Shutting down application...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_app.GRPC.Shutdown(shutdownCtx)

	case err := <-errCh:
		log.Error("gRPC server exited unexpectedly", slog.Any("err", err))
	}

	log.Info("Application stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	return log
}
