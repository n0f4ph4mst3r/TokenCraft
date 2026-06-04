package signer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
)

type Claims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	AppID  int64  `json:"app_id"`
	jwt.RegisteredClaims
}

type TokenSigner interface {
	SignJWT(user models.User, app models.App, ttl time.Duration) (string, error)
	SignOpaque(user models.User, app models.App, secret string) (string, error)
}

type DefaultTokenSigner struct {
	privateKey *rsa.PrivateKey
}

func (s *DefaultTokenSigner) SignJWT(user models.User, app models.App, ttl time.Duration) (string, error) {

	claims := Claims{
		UserID: user.ID.String(),
		Email:  user.Email,
		AppID:  app.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			Issuer:    "TokenCraft",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func NewSigner(privateKeyPath string) (*DefaultTokenSigner, error) {
	if privateKeyPath == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		return &DefaultTokenSigner{privateKey: key}, nil
	}

	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return nil, err
	}

	return &DefaultTokenSigner{privateKey: key}, nil
}

func (s *DefaultTokenSigner) SignOpaque(user models.User, app models.App, secret string) (string, error) {

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	key := []byte(secret + app.Secret)

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write([]byte(user.ID.String()))
	mac.Write([]byte(strconv.FormatInt(app.ID, 10)))

	sum := mac.Sum(nil)
	token := make([]byte, 0, len(nonce)+len(sum))
	token = append(token, nonce...)
	token = append(token, sum...)

	return base64.RawURLEncoding.EncodeToString(token), nil
}
