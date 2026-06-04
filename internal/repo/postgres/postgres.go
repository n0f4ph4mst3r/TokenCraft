package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/models"
	"github.com/n0f4ph4mst3r/TokenCraft/internal/repo"
	"github.com/pressly/goose/v3"
)

type pgStorage struct {
	dbPool *pgxpool.Pool
}

//go:embed migrations/*.sql
var embedMigrations embed.FS

func NewStorage(ctx context.Context, connStr string) (*pgStorage, error) {
	const op = "storage.postgres.New"

	dbPool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to open database: %w", op, err)
	}

	var retriesCount int
	for retriesCount = 0; retriesCount < 10; retriesCount++ {
		err = dbPool.Ping(ctx)
		if err == nil {
			break
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: unable to connect to database: %w", op, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}

	if retriesCount == 10 {
		return nil, fmt.Errorf("%s: retries exceeded: %w", op, err)
	}

	goose.SetBaseFS(embedMigrations)
	if err = goose.SetDialect("postgres"); err != nil {
		return nil, fmt.Errorf("failed to set goose dialect: %w", err)
	}

	fmt.Println("Running migrations...")
	db := stdlib.OpenDBFromPool(dbPool)
	if err := goose.Up(db, "migrations"); err != nil {
		return nil, fmt.Errorf("failed to apply migrations: %w", err)
	}
	if err := db.Close(); err != nil {
		return nil, fmt.Errorf("failed to close database connection after applying migrations: %w", err)
	}

	fmt.Println("Migrations applied successfully")

	return &pgStorage{dbPool: dbPool}, nil
}

func (s *pgStorage) UserById(
	ctx context.Context,
	userID uuid.UUID,
) (models.User, error) {
	const op = "storage.postgres.user.byId"

	const query = `
		SELECT id, email, username, password_hash
		FROM users
		WHERE id = $1
	`

	var user models.User
	row := s.dbPool.QueryRow(ctx, query, userID)
	if err := row.Scan(&user.ID, &user.Email, &user.Username, &user.Password); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, repo.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *pgStorage) UserByEmail(
	ctx context.Context,
	email string,
) (models.User, error) {
	const op = "storage.postgres.user.byEmail"

	const query = `
		SELECT id, email, username, password_hash
		FROM users
		WHERE email = $1
	`

	var user models.User
	row := s.dbPool.QueryRow(ctx, query, email)
	if err := row.Scan(&user.ID, &user.Email, &user.Username, &user.Password); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, repo.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *pgStorage) RegisterUser(
	ctx context.Context,
	email string,
	username string,
	hashPassword []byte,
) (models.User, error) {
	const op = "storage.postgres.user.register"

	const query = `
		INSERT INTO users (email, username, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, email, username, password_hash
	`

	var user models.User
	row := s.dbPool.QueryRow(
		ctx,
		query,
		email,
		username,
		hashPassword,
	)

	if err := row.Scan(&user.ID, &user.Email, &user.Username, &user.Password); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return models.User{}, repo.ErrUserExists
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *pgStorage) RoleCheck(
	ctx context.Context,
	refreshToken string,
	requiredRole string,
) error {
	const op = "storage.postgres.rolecheck"

	const query = `
		SELECT 1
		FROM tokens t
		JOIN user_app_roles uar
		  ON uar.user_id = t.user_id
		 AND uar.app_id = t.app_id
		JOIN roles r
		  ON r.id = uar.role_id
		 AND r.app_id = uar.app_id
		WHERE t.token_hash = $1
		  AND t.expires_at > now()
		  AND r.name = $2
	`

	var dummy int
	row := s.dbPool.QueryRow(
		ctx,
		query,
		refreshToken,
		requiredRole,
	)

	if err := row.Scan(&dummy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repo.ErrForbidden
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *pgStorage) GetUserRoles(
	ctx context.Context,
	userID uuid.UUID,
	appID int64,
) ([]string, error) {
	const op = "storage.postgres.roles.getUserRoles"

	const query = `
		SELECT r.name
		FROM user_app_roles uar
		JOIN roles r
		  ON r.id = uar.role_id
		 AND r.app_id = uar.app_id
		WHERE uar.user_id = $1
		  AND uar.app_id = $2
	`

	rows, err := s.dbPool.Query(ctx, query, userID, appID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return roles, nil
}

func (s *pgStorage) AppById(
	ctx context.Context,
	appID int64,
) (models.App, error) {
	const op = "storage.postgres.app.byId"

	const query = `
		SELECT id, name, secret
		FROM apps
		WHERE id = $1
	`

	var app models.App
	row := s.dbPool.QueryRow(ctx, query, appID)
	if err := row.Scan(&app.ID, &app.Name, &app.Secret); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, repo.ErrAppNotFound
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func (s *pgStorage) SaveToken(
	ctx context.Context,
	userID uuid.UUID,
	appID int64,
	tokenHash string,
	expiresAt time.Time,
) error {
	const op = "storage.postgres.token.save"

	const query = `
		INSERT INTO tokens (token_hash, user_id, app_id, expires_at)
		VALUES ($1, $2, $3, $4)
	`

	_, err := s.dbPool.Exec(ctx, query, tokenHash, userID, appID, expiresAt)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *pgStorage) GetToken(
	ctx context.Context,
	tokenHash string,
) (models.Token, error) {
	const op = "storage.postgres.token.get"

	const query = `
		SELECT user_id, app_id, expires_at
		FROM tokens
		WHERE token_hash = $1
	`

	var token models.Token
	row := s.dbPool.QueryRow(ctx, query, tokenHash)
	if err := row.Scan(&token.UserID, &token.AppID, &token.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Token{}, repo.ErrTokenNotFound
		}
		return models.Token{}, fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (s *pgStorage) RemoveToken(
	ctx context.Context,
	tokenHash string,
) error {
	const op = "storage.postgres.token.remove"

	const query = `
		DELETE FROM tokens
		WHERE token_hash = $1
	`

	res, err := s.dbPool.Exec(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if res.RowsAffected() == 0 {
		return repo.ErrTokenNotFound
	}

	return nil
}
