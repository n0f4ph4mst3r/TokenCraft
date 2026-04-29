-- +goose Up
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- +goose StatementBegin
CREATE FUNCTION set_updated_at()
RETURNS TRIGGER
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL,
    password_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE apps (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    app_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_roles_app
        FOREIGN KEY (app_id)
        REFERENCES apps(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_role_app_name
        UNIQUE (app_id, name),

    CONSTRAINT uq_role_id_app
        UNIQUE (id, app_id)
);


CREATE TABLE user_app_roles (
    user_id UUID NOT NULL,
    app_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    CONSTRAINT pk_user_app_roles
        PRIMARY KEY (user_id, app_id),

    CONSTRAINT fk_user_app_roles_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_user_app_roles_app
        FOREIGN KEY (app_id)
        REFERENCES apps(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_user_app_roles_role
        FOREIGN KEY (role_id, app_id)
        REFERENCES roles(id, app_id)
        ON DELETE CASCADE
);

CREATE TABLE tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL,
    app_id BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_tokens_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_tokens_app
        FOREIGN KEY (app_id)
        REFERENCES apps(id)
        ON DELETE CASCADE
);

CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_apps_updated_at
BEFORE UPDATE ON apps
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


CREATE TRIGGER trg_roles_updated_at
BEFORE UPDATE ON roles
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


CREATE TRIGGER trg_user_app_roles_updated_at
BEFORE UPDATE ON user_app_roles
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_tokens_updated_at
BEFORE UPDATE ON tokens
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE INDEX idx_users_email ON users(email);

CREATE INDEX idx_apps_name ON apps(name);

CREATE INDEX idx_tokens_user_id ON tokens(user_id);
CREATE INDEX idx_tokens_expires_at ON tokens(expires_at);

CREATE INDEX idx_user_app_roles_user_id ON user_app_roles(user_id);
CREATE INDEX idx_user_app_roles_app_id ON user_app_roles(app_id);
CREATE INDEX idx_user_app_roles_role_id ON user_app_roles(role_id);

-- +goose Down
DROP TABLE IF EXISTS tokens;
DROP TABLE IF EXISTS user_app_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS apps;
DROP TABLE IF EXISTS users;
DROP FUNCTION IF EXISTS set_updated_at();
DROP EXTENSION IF EXISTS "uuid-ossp";