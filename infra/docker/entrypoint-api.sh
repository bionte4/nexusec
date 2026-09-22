#!/bin/sh
# API container entrypoint: wait for DB, run Alembic, then exec CMD.
set -eu

echo "[entrypoint] waiting for database…"
python - <<'PY'
import os, sys, time
from urllib.parse import urlparse

url = os.environ.get("DATABASE_URL", "")
# asyncpg URL → host/port for TCP wait via psycopg
sync = url.replace("postgresql+asyncpg://", "postgresql://").replace(
    "postgresql+psycopg://", "postgresql://"
)
if not sync.startswith("postgresql"):
    print("[entrypoint] DATABASE_URL missing or invalid", file=sys.stderr)
    sys.exit(1)

import socket
from urllib.parse import urlparse

parsed = urlparse(sync)
host = parsed.hostname or "postgres"
port = parsed.port or 5432
deadline = time.time() + 60
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=2):
            print(f"[entrypoint] database reachable at {host}:{port}")
            break
    except OSError:
        time.sleep(1)
else:
    print("[entrypoint] database not reachable", file=sys.stderr)
    sys.exit(1)
PY

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  echo "[entrypoint] running alembic upgrade head…"
  cd /app
  alembic -c database/alembic.ini upgrade head
fi

cd /app/backend
exec "$@"
