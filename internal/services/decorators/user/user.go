package user

import (
	"context"
	"encoding/base64"

	"github.com/google/uuid"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/helpers/hasher"
)

type UserProvider interface {
	UserById(ctx context.Context, userID uuid.UUID) (models.User, error)
	UserByEmail(ctx context.Context, email string) (models.User, error)
	RegisterUser(
		ctx context.Context,
		email string,
		name string,
		hashPassword []byte) (models.User, error)
	RoleCheck(ctx context.Context, refreshToken string, role string) error
}

type UserDecorator struct {
	next           UserProvider
	passwordHasher hasher.Hasher
	tokenHasher    hasher.Hasher
}

func New(next UserProvider, passwordHasher hasher.Hasher, tokenHasher hasher.Hasher) *UserDecorator {
	if passwordHasher == nil {
		passwordHasher = hasher.BcryptHasher{}
	}

	if tokenHasher == nil {
		tokenHasher = hasher.Sha256Hasher{}
	}

	return &UserDecorator{
		next:           next,
		passwordHasher: passwordHasher,
		tokenHasher:    tokenHasher,
	}
}

func (d *UserDecorator) UserById(ctx context.Context, userID uuid.UUID) (models.User, error) {
	return d.next.UserById(ctx, userID)
}

func (d *UserDecorator) UserByEmail(ctx context.Context, email string) (models.User, error) {
	return d.next.UserByEmail(ctx, email)
}

func (d *UserDecorator) RegisterUser(ctx context.Context, email string, name string, password string) (models.User, error) {
	hash, err := d.passwordHasher.Hash(password)
	if err != nil {
		return models.User{}, err
	}

	return d.next.RegisterUser(ctx, email, name, hash)
}

func (d *UserDecorator) RoleCheck(ctx context.Context, refreshToken string, role string) error {
	hash, err := d.tokenHasher.Hash(refreshToken)
	if err != nil {
		return err
	}

	return d.next.RoleCheck(ctx, base64.RawURLEncoding.EncodeToString(hash[:]), role)
}
