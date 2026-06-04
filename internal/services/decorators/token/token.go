package token

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/services/helpers/hasher"
)

type TokenProvider interface {
	SaveToken(ctx context.Context, userID uuid.UUID, appID int64, token string, expiresAt time.Time) error
	GetToken(ctx context.Context, token string) (models.Token, error)
	RemoveToken(ctx context.Context, token string) error
}

type TokenDecorator struct {
	next   TokenProvider
	hasher hasher.Hasher
}

func New(next TokenProvider, tokenHasher hasher.Hasher) *TokenDecorator {
	if tokenHasher == nil {
		tokenHasher = hasher.Sha256Hasher{}
	}

	return &TokenDecorator{
		next:   next,
		hasher: tokenHasher,
	}
}

func (d *TokenDecorator) SaveToken(ctx context.Context, userID uuid.UUID, appID int64, token string, expiresAt time.Time) error {
	hashedToken, err := d.hasher.Hash(token)
	if err != nil {
		return err
	}

	return d.next.SaveToken(ctx, userID, appID, base64.RawURLEncoding.EncodeToString(hashedToken[:]), expiresAt)
}

func (d *TokenDecorator) GetToken(ctx context.Context, token string) (models.Token, error) {
	hashedToken, err := d.hasher.Hash(token)
	if err != nil {
		return models.Token{}, err
	}

	return d.next.GetToken(ctx, base64.RawURLEncoding.EncodeToString(hashedToken[:]))
}

func (d *TokenDecorator) RemoveToken(ctx context.Context, token string) error {
	hashedToken, err := d.hasher.Hash(token)
	if err != nil {
		return err
	}

	return d.next.RemoveToken(ctx, base64.RawURLEncoding.EncodeToString(hashedToken[:]))
}
