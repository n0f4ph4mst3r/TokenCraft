package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type cacheStorage struct {
	client *redis.Client
}

func NewCacheStorage(ctx context.Context, connStr string) (*cacheStorage, error) {
	const op = "storage.redis.New"

	if connStr == "" {
		return nil, fmt.Errorf("%s: empty connection string", op)
	}

	u, err := url.Parse(connStr)
	if err != nil {
		return nil, err
	}

	addr := u.Host

	db := 0
	if u.Path != "" {
		dbStr := strings.TrimPrefix(u.Path, "/")
		db, _ = strconv.Atoi(dbStr)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		DB:           db,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("%s: unable to connect: %w", op, err)
	}

	return &cacheStorage{client: client}, nil
}

func (r *cacheStorage) Get(ctx context.Context, key string, dest interface{}) (bool, error) {
	const op = "storage.redis.get"

	val, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s: %s", op, err)
	}

	return true, json.Unmarshal(val, dest)
}

func (r *cacheStorage) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	const op = "storage.redis.set"

	data, _ := json.Marshal(value)
	err := r.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		return fmt.Errorf("%s: %s", op, err)
	}

	return nil
}

func (r *cacheStorage) Del(ctx context.Context, keys ...string) error {
	const op = "storage.redis.delete"

	_, err := r.client.Del(ctx, keys...).Result()
	if err != nil {
		return fmt.Errorf("%s: %s", op, err)
	}

	return nil
}
