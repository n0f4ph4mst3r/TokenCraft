package hasher

import (
	"crypto/sha256"

	"golang.org/x/crypto/bcrypt"
)

type Hasher interface {
	Hash(str string) ([]byte, error)
}

type BcryptHasher struct{}

func (BcryptHasher) Hash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

type Sha256Hasher struct{}

func (Sha256Hasher) Hash(str string) ([]byte, error) {
	hash := sha256.Sum256([]byte(str))
	return hash[:], nil
}
