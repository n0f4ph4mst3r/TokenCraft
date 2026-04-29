package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID       uuid.UUID
	Username string
	Email    string
	Password []byte
}

type App struct {
	ID     int64
	Name   string
	Secret string
}

type Token struct {
	UserID    uuid.UUID
	AppID     int64
	ExpiresAt time.Time
}
