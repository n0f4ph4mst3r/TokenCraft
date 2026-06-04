package repo

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/config"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
)

var (
	ErrUserExists    = errors.New("user already exists")
	ErrUserNotFound  = errors.New("user not found")
	ErrInvalidPass   = errors.New("invalid password")
	ErrAppNotFound   = errors.New("app not found")
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenExpired  = errors.New("token expired")
	ErrForbidden     = errors.New("forbidden")
)

type AuthRepo struct {
	db DbProvider

	cache    CacheProvider
	cacheCfg *config.CacheConfig

	log *slog.Logger
}

type DbProvider interface {
	UserProvider
	AppProvider
	TokenProvider
}

type UserProvider interface {
	UserById(ctx context.Context, userID uuid.UUID) (models.User, error)

	UserByEmail(ctx context.Context, email string) (models.User, error)

	RegisterUser(
		ctx context.Context,
		email string,
		username string,
		hashPassword []byte,
	) (models.User, error)

	RoleCheck(ctx context.Context, refreshToken string, role string) error

	GetUserRoles(
		ctx context.Context,
		userID uuid.UUID,
		appID int64,
	) ([]string, error)
}

type AppProvider interface {
	AppById(ctx context.Context, appID int64) (models.App, error)
}

type TokenProvider interface {
	SaveToken(
		ctx context.Context,
		userID uuid.UUID,
		appID int64,
		tokenHash string,
		expiresAt time.Time,
	) error

	GetToken(
		ctx context.Context,
		tokenHash string,
	) (models.Token, error)

	RemoveToken(
		ctx context.Context,
		tokenHash string,
	) error
}

type CacheProvider interface {
	Get(ctx context.Context, key string, dest interface{}) (bool, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

func NewRepo(log *slog.Logger, db DbProvider, cache CacheProvider, cfg *config.CacheConfig) *AuthRepo {
	return &AuthRepo{
		log:      log,
		db:       db,
		cache:    cache,
		cacheCfg: cfg,
	}
}

func (r *AuthRepo) UserById(ctx context.Context, userID uuid.UUID) (models.User, error) {
	key := r.key("user", "id", userID.String())

	return cached(
		ctx,
		r.log,
		r.cache,
		key,
		r.cacheCfg.TTL,
		func() (models.User, error) {
			return r.db.UserById(ctx, userID)
		},
	)
}

func (r *AuthRepo) UserByEmail(ctx context.Context, email string) (models.User, error) {
	key := r.key("user", "email", email)

	return cached(
		ctx,
		r.log,
		r.cache,
		key,
		r.cacheCfg.TTL,
		func() (models.User, error) {
			return r.db.UserByEmail(ctx, email)
		},
	)
}

func (r *AuthRepo) RegisterUser(ctx context.Context, email string, username string, hashPassword []byte) (models.User, error) {
	user, err := r.db.RegisterUser(ctx, email, username, hashPassword)
	if err != nil {
		return models.User{}, err
	}

	if r.cache != nil {
		err := r.cache.Del(ctx,
			r.key("user", "id", user.ID.String()),
			r.key("user", "email", user.Email),
		)
		if err != nil {
			r.log.Warn("Redis DEL error", "key", r.key("user", "id", user.ID.String()), "err", err)
		}
	}

	return user, nil
}

func (r *AuthRepo) RoleCheck(ctx context.Context, tokenHash string, requiredRole string) error {
	token, err := r.GetToken(ctx, tokenHash)
	if err != nil {
		return err
	}

	roles, err := cached(
		ctx,
		r.log,
		r.cache,
		r.key("roles", token.UserID.String(), strconv.FormatInt(token.AppID, 10)),
		5*time.Minute,
		func() ([]string, error) {
			return r.db.GetUserRoles(ctx, token.UserID, token.AppID)
		},
	)

	if err != nil {
		return err
	}

	for _, role := range roles {
		if role == requiredRole {
			return nil
		}
	}

	return ErrForbidden
}

func (r *AuthRepo) AppById(ctx context.Context, appID int64) (models.App, error) {
	return cached(
		ctx,
		r.log,
		r.cache,
		r.key("app", strconv.FormatInt(appID, 10)),
		r.cacheCfg.TTL,
		func() (models.App, error) {
			return r.db.AppById(ctx, appID)
		},
	)
}

func (r *AuthRepo) SaveToken(
	ctx context.Context,
	userID uuid.UUID,
	appID int64,
	tokenHash string,
	expiresAt time.Time,
) error {

	if err := r.db.SaveToken(ctx, userID, appID, tokenHash, expiresAt); err != nil {
		return err
	}

	if r.cache != nil {
		token := models.Token{
			UserID:    userID,
			AppID:     appID,
			ExpiresAt: expiresAt,
		}

		err := r.cache.Set(
			ctx,
			r.key("token", tokenHash),
			token,
			time.Until(expiresAt),
		)

		if err != nil {
			r.log.Warn("Redis SET error", "key", r.key("token", tokenHash), "err", err)
		}
	}

	return nil
}

func (r *AuthRepo) GetToken(ctx context.Context, tokenHash string) (models.Token, error) {
	return cached(
		ctx,
		r.log,
		r.cache,
		r.key("token", tokenHash),
		r.cacheCfg.TTL,
		func() (models.Token, error) {
			return r.db.GetToken(ctx, tokenHash)
		},
	)
}

func (r *AuthRepo) RemoveToken(ctx context.Context, tokenHash string) error {
	if r.cache != nil {
		err := r.cache.Del(ctx, r.key("token", tokenHash))
		if err != nil {
			r.log.Warn("Redis DEL error", "key", r.key("token", tokenHash), "err", err)
		}
	}
	return r.db.RemoveToken(ctx, tokenHash)
}

func cached[T any](
	ctx context.Context,
	log *slog.Logger,
	cache CacheProvider,
	key string,
	ttl time.Duration,
	dbFn func() (T, error),
) (T, error) {
	if cache != nil {
		var cached T
		found, err := cache.Get(ctx, key, &cached)
		if err == nil && found {
			return cached, nil
		}

		if err != nil {
			log.Warn("Redis GET error", "key", key, "err", err)
		}
	}

	val, err := dbFn()
	if err != nil {
		var zero T
		return zero, err
	}

	if cache != nil {
		err = cache.Set(ctx, key, val, ttl)
		if err != nil {
			log.Warn("Redis SET error", "key", key, "err", err)
		}
	}

	return val, nil
}

func (r *AuthRepo) key(parts ...string) string {
	all := []string{
		r.cacheCfg.Prefix,
		r.cacheCfg.Version,
	}
	all = append(all, parts...)
	return strings.Join(all, ":")
}
