package auth

import (
	"context"
	"errors"
	"time"

	"github.com/n0f4ph4mst3r/TokenCraft/internal/grpc/auth/dto"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo"
	ssov1 "github.com/n0f4ph4mst3r/TokenCraft/protos/gen/go/sso"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type AuthService interface {
	RegisterUser(
		ctx context.Context,
		email string,
		name string,
		password string,
	) (models.User, error)
	Login(
		ctx context.Context,
		username,
		password string,
		appID int64,
	) (models.User, TokenPair, error)
	Logout(
		ctx context.Context,
		token string,
	) error
	UpdateToken(
		ctx context.Context,
		refreshToken string,
	) (TokenPair, error)
	RoleCheck(
		ctx context.Context,
		refreshToken string,
		role string,
	) (bool, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth       AuthService
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func NewAuthServer(auth AuthService, accessTTL, refreshTTL time.Duration) *serverAPI {
	return &serverAPI{
		auth:       auth,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func Register(gRPC *grpc.Server, auth AuthService, accessTTL time.Duration, refreshTTL time.Duration) {
	ssov1.RegisterAuthServer(gRPC, NewAuthServer(auth, accessTTL, refreshTTL))
}

func (s *serverAPI) RegisterUser(
	ctx context.Context,
	req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	input := &dto.Register{
		Auth: dto.Auth{
			Email:    req.GetEmail(),
			Password: req.GetPassword(),
		},
		Username: req.GetUsername(),
	}

	if err := dto.ValidateInput(input); err != nil {
		return nil, err
	}

	user, err := s.auth.RegisterUser(ctx, input.Email, input.Username, input.Password)
	if err != nil {
		return nil, mapError(err)
	}

	return &ssov1.RegisterResponse{
		UserId:   user.ID.String(),
		Username: user.Username,
		Email:    user.Email,
	}, nil
}

func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	input := &dto.Login{
		Auth: dto.Auth{
			Email:    req.GetEmail(),
			Password: req.GetPassword(),
		},
		App: req.GetAppId(),
	}

	if err := dto.ValidateInput(input); err != nil {
		return nil, err
	}

	user, tokens, err := s.auth.Login(ctx, input.Email, input.Password, input.App)
	if err != nil {
		return nil, mapError(err)
	}

	return &ssov1.LoginResponse{
		UserId:                user.ID.String(),
		Username:              user.Username,
		Email:                 user.Email,
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		AccessTokenExpiresIn:  int64(s.accessTTL / time.Second),
		RefreshTokenExpiresIn: int64(s.refreshTTL / time.Second),
	}, nil
}

func (s *serverAPI) Logout(
	ctx context.Context,
	req *ssov1.LogoutRequest) (*ssov1.LogoutResponse, error) {

	input := &dto.RefreshToken{
		Token: req.GetRefreshToken(),
	}

	if err := dto.ValidateInput(input); err != nil {
		return nil, err
	}

	if err := s.auth.Logout(ctx, input.Token); err != nil {
		return nil, mapError(err)
	}

	return &ssov1.LogoutResponse{
		Message: "logout successful",
	}, nil
}

func (s *serverAPI) RefreshToken(
	ctx context.Context,
	req *ssov1.RefreshTokenRequest) (*ssov1.RefreshTokenResponse, error) {

	input := &dto.RefreshToken{
		Token: req.GetRefreshToken(),
	}

	if err := dto.ValidateInput(input); err != nil {
		return nil, err
	}

	tokens, err := s.auth.UpdateToken(ctx, input.Token)
	if err != nil {
		return nil, mapError(err)
	}

	return &ssov1.RefreshTokenResponse{
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		AccessTokenExpiresIn:  int64(s.accessTTL / time.Second),
		RefreshTokenExpiresIn: int64(s.refreshTTL / time.Second),
	}, nil
}

func (s *serverAPI) RoleCheck(
	ctx context.Context,
	req *ssov1.RoleCheckRequest) (*ssov1.RoleCheckResponse, error) {

	input := &dto.RoleCheck{
		RefreshToken: dto.RefreshToken{
			Token: req.GetRefreshToken(),
		},
		Role: req.GetRequiredRole(),
	}

	if err := dto.ValidateInput(input); err != nil {
		return nil, err
	}

	passCheck, err := s.auth.RoleCheck(ctx, input.RefreshToken.Token, input.Role)
	if err != nil {
		return nil, mapError(err)
	}

	return &ssov1.RoleCheckResponse{
		PassCheck: passCheck,
	}, nil
}

func mapError(err error) error {
	switch {
	case errors.Is(err, bcrypt.ErrHashTooShort):
		return status.Error(codes.InvalidArgument, "password hash error - too short")

	case errors.Is(err, bcrypt.ErrPasswordTooLong):
		return status.Error(codes.InvalidArgument, "password hash error - too long")

	case errors.Is(err, repo.ErrUserExists):
		return status.Error(codes.AlreadyExists, "user already exists")

	case errors.Is(err, repo.ErrUserNotFound),
		errors.Is(err, repo.ErrInvalidPass):
		return status.Error(codes.Unauthenticated, "invalid credentials")

	case errors.Is(err, repo.ErrAppNotFound):
		return status.Error(codes.NotFound, "application not found")

	case errors.Is(err, repo.ErrTokenNotFound),
		errors.Is(err, repo.ErrTokenExpired):
		return status.Error(codes.Unauthenticated, "invalid or expired token")

	case errors.Is(err, repo.ErrForbidden):
		return status.Error(codes.PermissionDenied, "access denied")

	default:
		return status.Error(codes.Internal, "internal service error")
	}
}
