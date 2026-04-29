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
)

type App struct {
	GRPC *gRPC.App
}

func New(
	ctx context.Context,
	log *slog.Logger,
	grpcPort int,
	dbURL string,
	cacheCfg *config.CacheConfig,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	secret string,
) *App {
	pgStartupCtx, pgStartupCancel := context.WithTimeout(ctx, 10*time.Second)
	defer pgStartupCancel()

	log.Info("Initializing storage...")
	pgStorage, err := postgres.NewStorage(pgStartupCtx, dbURL)
	if err != nil {
		log.Error("Failed to initialize storage", "err", err)
		panic(err)
	}
	log.Info("Storage initialized successfully")

	redisStartupCtx, redisStartupCancel := context.WithTimeout(ctx, 10*time.Second)
	defer redisStartupCancel()

	log.Info("Initializing cache...")
	redis, err := redis.NewCacheStorage(redisStartupCtx, cacheCfg.Url)
	if err != nil {
		log.Warn(err.Error())
	}
	log.Info("Cache initialized successfully")

	repo := repo.NewRepo(log, pgStorage, redis, cacheCfg)

	authSvc := auth.NewAuthService(log, repo, accessTTL, refreshTTL, secret, hasher.BcryptHasher{}, hasher.Sha256Hasher{}, nil)

	grpcApp, err := gRPC.New(log, grpcPort, authSvc, accessTTL, refreshTTL)
	if err != nil {
		log.Error("failed to init grpc app", "err", err)
		panic(err)
	}

	return &App{
		GRPC: grpcApp,
	}
}
