# fastapi-kit

A lightweight FastAPI boilerplate to start APIs quickly. This project provides a small, opinionated starter kit with authentication helpers, API key support, rate limiting primitives, Redis integration and Alembic migrations so you can begin building production-ready APIs fast.

## Highlights

- FastAPI app with router organization (`api/routers`) for auth, users and API keys
- OAuth2 / JWT token helpers (in `api/oauth2.py`) and auth router
- SQLAlchemy (session, models) and Alembic migration setup
- Redis client and rate-limiting helpers
- Logging configured with rotating file handler

## Prerequisites

- Python 3.11+ (the project uses modern pydantic-settings and FastAPI)
- PostgreSQL, MySQL & MariaDB, SQLite, Oracle, and Microsoft SQL Server for persistent storage
- Redis for rate-limiting / lockout features

### Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Environment

Create a `.env` file at the project root (the project uses pydantic-settings to load `.env`). The project expects at least the following variables (see `core/config.py`):

- DATABASE_URL - SQLAlchemy database url, e.g. `postgresql://user:pass@localhost:5432/dbname`
- SECRET_KEY - JWT secret key
- ALGORITHM - JWT algorithm (e.g. `HS256`)
- ACCESS_TOKEN_EXPIRE_MINUTES - token lifetime in minutes
- REDIS_HOST - redis host (e.g. `127.0.0.1`)
- REDIS_PORT - redis port (e.g. `6379`)
- RATE_LIMIT_PER_HOUR - global rate limit per hour
- USER_RATE_LIMIT_PER_HOUR - per-user rate limit per hour
- MAX_FAILED_ATTEMPTS - max failed login attempts before lockout
- LOCKOUT_DURATION_SECONDS - lockout duration in seconds
- HEARTBEAT_INTERVAL_SECONDS - used by background/monitoring features

Example `.env` (do not commit credentials):

```env
DATABASE_URL=postgresql://postgres:password@localhost:5432/fastapi_db
SECRET_KEY=your-long-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
RATE_LIMIT_PER_HOUR=1000
USER_RATE_LIMIT_PER_HOUR=500
MAX_FAILED_ATTEMPTS=5
LOCKOUT_DURATION_SECONDS=3600
HEARTBEAT_INTERVAL_SECONDS=60
```

## Database migrations (Alembic)

The repo includes an `alembic` folder. Create your database, then generate and run migrations:

```bash
# create a migration (after editing/adding models)
alembic revision --autogenerate -m "create initial tables"
# apply migrations
alembic upgrade head
```

## Run locally

Start the app with uvicorn from the project root:

```bash
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

Open http://127.0.0.1:8000/docs for the interactive OpenAPI docs.

## Project structure (important files)

- `api/` - FastAPI application package
	- `main.py` - app factory and middleware (CORS, logging)
	- `oauth2.py` - JWT / token helpers
	- `rate_limiter.py` - request rate limiting helpers
	- `routers/` - grouped routers: `auth.py`, `user.py`, `api_keys.py`
- `core/` - core infra and settings
	- `config.py` - application settings (loaded from `.env`)
	- `database.py` - SQLAlchemy engine, SessionLocal, Base
	- `models.py` - SQLAlchemy models (domain entities)
	- `redis_client.py` - Redis connection helper
- `alembic/` - database migrations
- `requirements.txt` - pinned dependencies

## API overview

The starter exposes a few routers already wired into `api/main.py`:

- `GET /` - root; a small welcome payload
- `auth` routes - login, token endpoints (see `api/routers/auth.py`)
- `user` routes - user management (see `api/routers/user.py`)
- `api_keys` routes - API key creation/management (see `api/routers/api_keys.py`)

Explore the code in `api/routers` to see exact paths and payloads. The OpenAPI docs at `/docs` will show the current endpoints.

## API Key authentication

This starter supports two authentication methods side-by-side: JWT Bearer tokens and API keys. The authentication dependency (`get_current_user`) will try a Bearer token first, then fall back to an API key if present.

Key points:

- Header name: `X-API-Key` — include your API key in this header when calling protected endpoints.
- API keys are returned only once when created (the raw key). The service stores a hashed version in the database and caches key metadata in Redis.
- Create an API key (requires an authenticated user using a JWT):

	- POST `/api-keys/` with an optional JSON body `{ "days": 30 }` to set the number of days the key will be valid (defaults to 30).
	- Response: `{ "api_key": "tf_<secret>", "expires_at": "<iso-datetime>" }` — store the `api_key` securely; it will not be shown again.

- List your API keys (safe metadata only):

	- GET `/api-keys/` — returns non-secret metadata (id, created_at, expires_at, is_active).

- Revoke an API key:

	- DELETE `/api-keys/{key_id}` — removes the key from the DB and cache. Requires the owning user's authentication.

- Example: call a protected endpoint using an API key

```bash
# Use X-API-Key header (no Bearer token required when using a valid API key)
curl -H "X-API-Key: tf_your_generated_key_here" http://127.0.0.1:8000/some/protected/endpoint
```

- Example: create an API key (you must be logged in and include a Bearer token)

```bash
curl -X POST http://127.0.0.1:8000/api-keys/ \
	-H "Authorization: Bearer <your_jwt_token>" \
	-H "Content-Type: application/json" \
	-d '{"days":30}'
```

Security and behavior notes:

- API keys are hashed before storage (the raw value is only returned on creation).
- The system uses Redis caching to improve lookup performance. After multiple cache misses the code will perform a DB lookup and update last-used timestamps.
- The app implements IP-based lockout and failed-attempt tracking in Redis. Repeated invalid attempts with API keys (or failed auth attempts) can trigger temporary lockout. Default thresholds come from the `.env` settings (`MAX_FAILED_ATTEMPTS`, `LOCKOUT_DURATION_SECONDS`).
- Rate limits are applied to the API key endpoints using the `user_rate_limiter` dependency; tune `USER_RATE_LIMIT_PER_HOUR` in `.env`.

## Logging

Logging is configured in `api/main.py` with a rotating file handler writing to `logs/app.log` by default. The app also logs to stdout so containerized setups will capture logs.

## Contributing

This repository is intended to be used as a starter template:

- Fork or clone the repo
- Update `.env` with your secrets and DB connection
- Add your models to `core/models.py` and create migrations
- Implement endpoints under `api/routers` and add tests

## Troubleshooting

- If migrations fail, ensure `DATABASE_URL` is valid and reachable.
- If Redis features fail, ensure Redis is running and `REDIS_HOST`/`REDIS_PORT` match.

## License

This project is provided under the terms in `LICENSE.md` (MIT License).

---

If you'd like, I can also:

- add a `Makefile` or a `dev` script to simplify common commands
- add a sample `.env.example` file
- add a minimal `docker-compose.yml` to bring up Postgres + Redis + the app for local development

If you want any of the above, tell me which and I'll add it.

