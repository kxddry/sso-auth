# sso-auth

sso-auth is a Single Sign-On (SSO) JWT-token based authentication service written in Go. It provides user authentication, registration, and app management with PostgreSQL as the backend database.

## Features

- User registration and login with email or username
- Password validation with configurable rules
- App management (register, retrieve apps)
- Database migrations using [golang-migrate](https://github.com/golang-migrate/migrate)
- Configuration via YAML file

## Getting Started

### Prerequisites

- Go 1.20+
- PostgreSQL
- [golang-migrate](https://github.com/golang-migrate/migrate)
- [Taskfile](https://taskfile.dev/)

### Configuration

Create a `config.yaml` file -- example in ./config/local.yaml
Create a `migrations.yaml` file -- example in ./config/migrations.yaml

### Run
 
- `task run` to automatically migrate and start the application;
- `task migrate` to create necessary PostgreSQL tables;
- `task migrate_down` to drop the created PostgreSQL tables;
- `task migrate_test` to create PostgreSQL tables for testing;
- `task migrate_test_down` to drop them;
- `task run_test` to run the server with the database for testing.