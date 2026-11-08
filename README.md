# FastAPI RBAC Auth System

A lightweight, async authentication and Role-Based Access Control (RBAC) backend built with **FastAPI**, **SQLAlchemy 2.0 (async)**, **PostgreSQL (`asyncpg`)**, and **Redis**.

The system provides declarative endpoint access guards, stateless JWT authentication, and Redis-backed session management with refresh token rotation and reuse detection.

---

## Getting Started & Server Start

### 1. Prerequisites
- Python >= 3.13
- [uv](https://docs.astral.sh/uv/) (recommended)
- PostgreSQL & Redis instances running locally or via Docker

### 2. Setup
Install project dependencies:
```bash
uv sync
```

Set up your environment variables:
```bash
cp .env.example .env
```
*(Ensure `DATABASE_URL` and `REDIS_URL` in `.env` point to your running databases.)*

Apply database migrations:
```bash
alembic upgrade head
```

### 3. Start the Server
Run the FastAPI development server with hot-reload enabled:
```bash
uv run uvicorn app.main:app --reload
```
*(Alternatively: `python -m app.main`)*

- **API Base URL:** `http://127.0.0.1:8000/api/v1`
- **Interactive API Documentation (Scalar):** `http://127.0.0.1:8000/docs`

---

## How Account Creation Currently Works

In the current implementation, user registration (`POST /api/v1/users`) is protected by `@Roles(Role.ADMIN)`. There is no public, unauthenticated signup endpoint; new accounts must be provisioned by an authenticated Admin.

Because creating users requires an active Admin Bearer token, the initial Administrator account must be bootstrapped using one of two methods:

### Method 1: Generate an Initial Admin Access Token (Recommended)
You can mint an admin JWT directly using the project's secret key without needing an existing user in the database:

```python
import uuid
from app.roles import Role
from app.security import create_access_token

admin_token = create_access_token(user_id=uuid.uuid4(), role=Role.ADMIN)
print(f"Bearer {admin_token}")
```

Use this token in the `Authorization` header (`Bearer <token>`) to call `POST /api/v1/users` and create your first persistent user accounts:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "secure_password"}'
```

### Method 2: Direct Database Seeding
You can insert an initial user directly into the PostgreSQL `users` table, hashing the password using `bcrypt`:
```python
from app.hash import hash_password

hashed = hash_password("secure_password")
# Insert user with this password_hash and link to an ADMIN role
```

---

## Current Features

- **Declarative Role-Based Access Control (RBAC):**
  - Route authorization via `@Roles(Role.ADMIN, ...)` decorator and `RolesGuard` dependency.
  - Zero-database overhead during requests by verifying roles directly from validated JWT claims.
  - Returns `401 Unauthorized` for missing/invalid tokens and `403 Forbidden` for role mismatches.

- **Stateless JWT Authentication:**
  - HMAC-SHA256 (`HS256`) access token creation and verification (`app/security.py`).
  - Configurable expiration (`ACCESS_TOKEN_EXPIRE_MINUTES`).

- **Redis Session Management & Token Rotation:**
  - Fast session storage and TTL eviction matching refresh token lifespans.
  - **Token Rotation:** Exchanging a refresh token via `POST /api/v1/auth/refresh` issues a new token pair and invalidates the previous refresh token.
  - **Reuse Detection:** Attempting to reuse an already-rotated or revoked refresh token triggers immediate user-wide session invalidation in Redis and logs revocation audit reasons in PostgreSQL.
  - Instant session termination and revocation check via `POST /api/v1/auth/logout`.

- **Credential Security & Brute-Force Lockout:**
  - Passwords hashed with `bcrypt` (never stored in plaintext).
  - Account lockout mechanism: 5 consecutive failed login attempts trigger an automatic 15-minute account lockout.

- **Async PostgreSQL & Migrations:**
  - Built with SQLAlchemy 2.0 async engine and `asyncpg`.
  - Database schema migrations managed via Alembic.

- **Interactive Documentation:**
  - Clean API documentation powered by [Scalar](https://scalar.com) served at `/docs`.
