# Database package

Alembic migrations for NexuSec. SQLAlchemy models live in `backend/app/models`.

```bash
# From repository root
alembic -c database/alembic.ini revision --autogenerate -m "describe change"
alembic -c database/alembic.ini upgrade head
```
