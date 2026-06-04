package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/n0f4ph4mst3r/TokenCraft/internal/config"
	gRPC "github.com/n0f4ph4mst3r/TokenCraft/internal/grpc"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo/postgres"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo/redis"
	auth "github.com/n0f4ph4mst3r/TokenCraft/internal/services"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/helpers/hasher"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/helpers/signer"
)

type App struct {
	GRPC *gRPC.App
}

func New(
	ctx context.Context,
	log *slog.Logger,
	cfg *config.Config,
) *App {
	pgStartupCtx, pgStartupCancel := context.WithTimeout(ctx, 10*time.Second)
	defer pgStartupCancel()

	log.Info("Initializing storage...")
	pgStorage, err := postgres.NewStorage(pgStartupCtx, cfg.DatabaseURL)
	if err != nil {
		log.Error("Failed to initialize storage", "err", err)
		panic(err)
	}
	log.Info("Storage initialized successfully")

	redisStartupCtx, redisStartupCancel := context.WithTimeout(ctx, 10*time.Second)
	defer redisStartupCancel()

	log.Info("Initializing cache...")
	redis, err := redis.NewCacheStorage(redisStartupCtx, cfg.Cache.Url)
	if nil == err {
		log.Info("Cache initialized successfully")
	} else {
		log.Warn(err.Error())
	}

	repo := repo.NewRepo(log, pgStorage, redis, &cfg.Cache)

	if cfg.RS256PrivateKeyPath != "" {
		log.Info("Using provided RS256 private key", slog.String("path", cfg.RS256PrivateKeyPath))
	} else {
		log.Warn("No RS256 private key path provided, using temporary key")
	}

	tokenSigner, err := signer.NewSigner(cfg.RS256PrivateKeyPath)
	if err != nil {
		log.Error("failed to initialize token signer", "err", err)
		panic(err)
	}

	authSvc := auth.NewAuthService(
		log,
		repo,
		cfg.JwtTTL,
		cfg.TokenTTL,
		cfg.Secret,
		hasher.BcryptHasher{},
		hasher.Sha256Hasher{},
		tokenSigner,
	)

	grpcApp, err := gRPC.New(log, cfg.GRPC.Port, authSvc, cfg.JwtTTL, cfg.TokenTTL)
	if err != nil {
		log.Error("failed to init grpc app", "err", err)
		panic(err)
	}

	return &App{
		GRPC: grpcApp,
	}
}
