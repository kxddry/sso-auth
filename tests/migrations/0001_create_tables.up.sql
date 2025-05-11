CREATE TABLE IF NOT EXISTS users
(
    id SERIAL PRIMARY KEY,
    email VARCHAR(320) UNIQUE NOT NULL,
    username VARCHAR(32) UNIQUE NOT NULL,
    pass_hash BYTEA NOT NULL
);
-- indices are already created for unique variables

CREATE TABLE IF NOT EXISTS apps
(
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) UNIQUE NOT NULL,
    secret TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS admins
(
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL DEFAULT 'admin' -- 'superadmin', 'editor', etc.
);