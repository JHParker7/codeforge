# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**CodeForge** is a WIP modular self-hosted CI/CD platform. The currently implemented service is **Gatekeeper** — a Go-based authentication microservice. Planned services include: overseer, architect, foundary, worklist, vault, and shopfront.

## Development Commands

### Local Development

Start the local PostgreSQL database:
```bash
cd infra/local && docker compose up
```

Run the gatekeeper service locally:
```bash
cd src/gatekeeper && go run main.go
```

### Building

Build the gatekeeper Docker image:
```bash
docker build -t gatekeeper:test src/gatekeeper
```

Build the Go binary directly:
```bash
cd src/gatekeeper && go build ./...
```

### Testing

Run integration tests (requires PostgreSQL and gatekeeper running):
```bash
pytest tests/integration_tests
```

Run Go unit tests:
```bash
cd src/gatekeeper && go test ./...
```

Run a single Go test:
```bash
cd src/gatekeeper && go test ./auth/... -run TestName
```

Full local CI pipeline (builds Docker image, starts infra, runs integration tests, tears down):
```bash
bash cicd/local_test.sh
```

### GraphQL Code Generation

When modifying GraphQL schemas (`src/gatekeeper/graph/*.graphqls`):
```bash
cd src/gatekeeper && go run github.com/99designs/gqlgen generate
```

## Architecture

### Gatekeeper (`src/gatekeeper/`)

REST API on port **8081** using the **Gin** framework. Host validation restricts requests to `127.0.0.1:8081`. Security headers (CSP, HSTS, X-Frame-Options) are applied globally.

**Route structure:**
- `POST /signup` — User registration
- `GET /token` — Login, returns JWT
- `GET /signin` — Sign-in handler
- `PUT /user/:id`, `DELETE /user/:id`, `GET /user/:id` — Authenticated user CRUD

**Auth flow:**
- Passwords are hashed with **Argon2id**; hash parameters (time, memory, threads, salt length, key length) are stored per-org in `auth.orgs`
- JWTs are signed with **Ed25519** (`auth/private.pem`)
- The `Authenticate()` middleware in `routes/auth.go` validates the JWT from `Authorization: Bearer:` header, then verifies claims match the database user
- Sessions are stored in `auth.sessions` with a public key for signature verification

**Package layout:**
- `auth/` — JWT creation/validation, role logic
- `database/` — PostgreSQL operations (pgx connection pool in `utils.go`)
- `routes/` — Gin handlers and `Authenticate` middleware
- `types/` — Shared domain types (`User`, `Session`, `Role`, `Team`, `Org`, `Service`, `Host`) and auth types (`APIResponse`, `JWTClaim`)

### Database

PostgreSQL 14 with schema in `sql/auth/setup.sql_script`. Tables live in the `auth` schema. Local dev credentials: `postgres:test`, database: `codeforge`. The Docker Compose setup auto-applies the SQL script on first start.

Key relationships: users → orgs → teams → roles; services → hosts.

### Infrastructure

- Local dev: `infra/local/compose.yml` (PostgreSQL only)
- Each service has its own `Dockerfile` using multi-stage Go builds
