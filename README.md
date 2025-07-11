# sso-auth

sso-auth is a Single Sign-On (SSO) JWT-token based authentication service written in Go. It provides user authentication, registration, and app management with PostgreSQL as the backend database.

## Features

- User registration and login with email or username
- Password validation with configurable rules
- App management (register, retrieve apps)
- Database migrations using [golang-migrate](https://github.com/golang-migrate/migrate)
- Configuration via YAML file

# 🚀 Quick Start

## Getting Started

### Prerequisites

- Docker / Podman
- PostgreSQL (optional if using the Docker Compose postgres service)

### Configuration

Edit your configuration YAML file as needed and set environment variables for Docker Compose if required.

---

### Run

Use Docker Compose to run migrations and start the app:


- **Start services**:

```bash
docker-compose up
```


- **Stop services**:

```bash
docker-compose down
```

- **Start migration (up)**:
```bash
- docker-compose up migration
```

- **Start migration (down)**:
```bash
- OPERATION=down docker-compose up migration 
```


---

### Notes

- The `migrator` service runs migrations using `golang-migrate`.
- The `app` service starts the authentication server.
- Both services depend on the `postgres` service if you use the included PostgreSQL container.

---