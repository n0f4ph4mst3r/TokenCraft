package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	authgrpc "github.com/n0f4ph4mst3r/TokenCraft/internal/grpc/auth"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/decorators/token"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/decorators/user"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/helpers/hasher"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/helpers/signer"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/sl"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInternal = errors.New("internal error")
)

type AuthService struct {
	log           *slog.Logger
	userProvider  UserProvider
	tokenProvider TokenProvider
	appProvider   AppProvider
	accessTTL     time.Duration
	refreshTTL    time.Duration
	secret        string
	tokenSigner   signer.TokenSigner
}

func NewAuthService(
	log *slog.Logger,
	authProvider AuthProvider,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	secret string,
	passwordHasher hasher.Hasher,
	tokenHasher hasher.Hasher,
	tokenSigner signer.TokenSigner,
) *AuthService {
	if tokenSigner == nil {
		tokenSigner = signer.DefaultTokenSigner{}
	}

	userProvider := user.New(authProvider, passwordHasher, tokenHasher)
	tokenProvider := token.New(authProvider, tokenHasher)

	return &AuthService{
		log:           log,
		userProvider:  userProvider,
		tokenProvider: tokenProvider,
		appProvider:   authProvider,
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		secret:        secret,
		tokenSigner:   tokenSigner,
	}
}

type AuthProvider interface {
	user.UserProvider
	AppProvider
	TokenProvider
}

type UserProvider interface {
	UserById(ctx context.Context, userID uuid.UUID) (models.User, error)
	UserByEmail(ctx context.Context, email string) (models.User, error)
	RegisterUser(
		ctx context.Context,
		email string,
		name string,
		password string) (models.User, error)
	RoleCheck(ctx context.Context, refreshToken string, role string) error
}

type AppProvider interface {
	AppById(ctx context.Context, appID int64) (models.App, error)
}

type TokenProvider interface {
	SaveToken(
		ctx context.Context,
		userID uuid.UUID,
		appID int64,
		token string,
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

func (a *AuthService) RegisterUser(
	ctx context.Context,
	email string,
	name string,
	password string,
) (models.User, error) {
	const op = "services.auth.register"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", sl.MaskEmail(email)),
		slog.String("name", name),
	)
	log.Info("registering user")

	user, err := a.userProvider.RegisterUser(ctx, email, name, password)
	if err != nil {
		if errors.Is(err, repo.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))
			return models.User{}, fmt.Errorf("%s: %w", op, repo.ErrUserExists)
		}

		if errors.Is(err, bcrypt.ErrHashTooShort) {
			log.Warn("password too short", sl.Err(err))
			return models.User{}, fmt.Errorf("%s: %w", op, bcrypt.ErrHashTooShort)
		}

		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			log.Warn("password too long", sl.Err(err))
			return models.User{}, fmt.Errorf("%s: %w", op, bcrypt.ErrPasswordTooLong)
		}

		log.Error("failed to save user", sl.Err(err))
		return models.User{}, ErrInternal
	}

	return user, nil
}

func (a *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
	appID int64,
) (models.User, authgrpc.TokenPair, error) {
	const op = "services.auth.login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", sl.MaskEmail(email)),
	)
	log.Info("attempting user login")

	user, err := a.userProvider.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repo.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return models.User{}, authgrpc.TokenPair{}, repo.ErrUserNotFound
		}

		log.Error("failed to get user", sl.Err(err))
		return models.User{}, authgrpc.TokenPair{}, ErrInternal
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Warn("wrong password attempt", sl.Err(err))
			return models.User{}, authgrpc.TokenPair{}, repo.ErrInvalidPass
		}

		log.Error("bcrypt error", sl.Err(err))
		return models.User{}, authgrpc.TokenPair{}, ErrInternal
	}

	app, err := a.appProvider.AppById(ctx, appID)
	if err != nil {
		if errors.Is(err, repo.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))
			return models.User{}, authgrpc.TokenPair{}, repo.ErrAppNotFound
		}

		log.Error("failed to get app", sl.Err(err))
		return models.User{}, authgrpc.TokenPair{}, ErrInternal
	}

	log.Info("user logged in successfully")

	tokens, err := a.issueTokens(ctx, user, app)
	if err != nil {
		log.Error("failed to issue new tokens", sl.Err(err))
		return models.User{}, authgrpc.TokenPair{}, ErrInternal
	}

	return user, tokens, nil
}

func (a *AuthService) Logout(
	ctx context.Context,
	token string,
) error {
	const op = "services.auth.logout"

	log := a.log.With(
		slog.String("op", op),
	)
	log.Info("logging out user")

	err := a.invalidateToken(ctx, log, token)
	if err != nil && !errors.Is(err, repo.ErrTokenNotFound) {
		log.Error("logout error", sl.Err(err))
		return ErrInternal
	}

	return nil
}

func (a *AuthService) UpdateToken(
	ctx context.Context,
	refreshToken string,
) (authgrpc.TokenPair, error) {
	const op = "services.auth.token"

	log := a.log.With(
		slog.String("op", op),
	)
	log.Info("refreshing tokens")

	tokenData, err := a.validateToken(ctx, log, refreshToken)
	if err != nil {
		return authgrpc.TokenPair{}, err
	}

	user, err := a.userProvider.UserById(ctx, tokenData.UserID)
	if err != nil {
		if errors.Is(err, repo.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			a.invalidateToken(ctx, log, refreshToken)
			return authgrpc.TokenPair{}, repo.ErrUserNotFound
		}

		log.Error("failed to get user", sl.Err(err))
		return authgrpc.TokenPair{}, ErrInternal
	}

	app, err := a.appProvider.AppById(ctx, tokenData.AppID)
	if err != nil {
		if errors.Is(err, repo.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))
			a.invalidateToken(ctx, log, refreshToken)
			return authgrpc.TokenPair{}, repo.ErrAppNotFound
		}

		log.Error("failed to get app", sl.Err(err))
		return authgrpc.TokenPair{}, ErrInternal
	}

	err = a.invalidateToken(ctx, log, refreshToken)
	if err != nil {
		return authgrpc.TokenPair{}, ErrInternal
	}

	tokens, err := a.issueTokens(ctx, user, app)
	if err != nil {
		log.Error("failed to issue new tokens", sl.Err(err))
		return authgrpc.TokenPair{}, ErrInternal
	}

	log.Info("tokens refreshed successfully")

	return tokens, nil
}

func (a *AuthService) RoleCheck(
	ctx context.Context,
	refreshToken string,
	requiredRole string,
) (bool, error) {
	const op = "services.auth.rolecheck"

	log := a.log.With(
		slog.String("op", op),
	)
	log.Info("checking user role")

	_, err := a.validateToken(ctx, log, refreshToken)
	if err != nil {
		return false, err
	}

	err = a.userProvider.RoleCheck(ctx, refreshToken, requiredRole)
	if err != nil {
		log.Error("role check failed", sl.Err(err))
		if errors.Is(err, repo.ErrForbidden) {
			return false, repo.ErrForbidden
		}

		return false, ErrInternal
	}

	log.Info("role check passed successfully")

	return true, nil
}

func (a *AuthService) issueTokens(
	ctx context.Context,
	user models.User,
	app models.App,
) (authgrpc.TokenPair, error) {
	accessToken, err := a.tokenSigner.SignJWT(user, app, a.accessTTL)
	if err != nil {
		return authgrpc.TokenPair{}, err
	}

	refreshToken, err := a.tokenSigner.SignOpaque(user, app, a.secret)
	if err != nil {
		return authgrpc.TokenPair{}, err
	}

	err = a.tokenProvider.SaveToken(ctx, user.ID, app.ID, refreshToken, time.Now().Add(a.refreshTTL))
	if err != nil {
		return authgrpc.TokenPair{}, err
	}

	return authgrpc.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (a *AuthService) validateToken(ctx context.Context, log *slog.Logger, token string) (models.Token, error) {
	log.Info("validating refresh token")

	tokenData, err := a.tokenProvider.GetToken(ctx, token)
	if err != nil {
		if errors.Is(err, repo.ErrTokenNotFound) {
			log.Error("refresh token not found")
			return models.Token{}, repo.ErrTokenNotFound
		}

		log.Error("failed to get refresh token", sl.Err(err))
		return models.Token{}, ErrInternal
	}

	if time.Now().After(tokenData.ExpiresAt) {
		log.Error("refresh token expired")
		a.invalidateToken(ctx, log, token)
		return models.Token{}, repo.ErrTokenExpired
	}

	log.Info("refresh token validated successfully")

	return tokenData, nil
}

func (a *AuthService) invalidateToken(ctx context.Context, log *slog.Logger, token string) error {
	err := a.tokenProvider.RemoveToken(ctx, token)
	if err != nil {
		if errors.Is(err, repo.ErrTokenNotFound) {
			log.Warn("cant remove refresh token, not found")
			return repo.ErrTokenNotFound
		}

		log.Error("cant remove refresh token", sl.Err(err))
		return err
	}

	return nil
}
