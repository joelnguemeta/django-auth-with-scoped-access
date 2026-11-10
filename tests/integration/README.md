# PostgreSQL and Redis integration tests

The CI integration job runs these tests against PostgreSQL 16 and Redis 7.
They exercise PostgreSQL row locks and concurrent lifecycle operations, and
real Redis token consumption from independent processes.

To run locally, start isolated PostgreSQL and Redis instances and run:

```sh
uv sync --group dev --group integration
DJANGO_SETTINGS_MODULE=tests.integration.settings uv run --no-sync pytest tests/integration -q
```

The settings default to PostgreSQL on `127.0.0.1:5432` as `postgres`, and
Redis database 15 on `127.0.0.1:6379`. Override these with
`SCOPED_TEST_PGHOST`, `SCOPED_TEST_PGPORT`, `SCOPED_TEST_PGUSER`, and
`SCOPED_TEST_REDIS_URL`. The PostgreSQL user needs permission to create and
drop Django's test database. Use disposable services: the tests create a
database and write temporary cache keys.
