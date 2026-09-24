-- SecuriX Auth Users — Postgres table for login / create-user
-- Runs automatically in docker (init-scripts) and can be pasted in pgAdmin.
-- No static users: everything is stored here via the FastAPI auth-service.

CREATE TABLE IF NOT EXISTS app_users (
    id            SERIAL PRIMARY KEY,
    name          VARCHAR(128) NOT NULL,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(32)  NOT NULL DEFAULT 'analyst',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_app_users_email ON app_users (LOWER(email));
