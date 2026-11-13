"""Alembic environment.

The URL comes from application settings rather than alembic.ini, so a
deployment configures the database in exactly one place. Async drivers are
rewritten to their synchronous equivalents because Alembic runs its migrations
synchronously.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import get_settings
from app.database.base import Base
from app.models import *  # noqa: F401,F403 - import models so metadata is populated

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def database_url() -> str:
    settings = get_settings()
    # The SQLite file lives under the data directory, which may not exist yet
    # on a first run.
    settings.ensure_directories()
    url = settings.resolved_database_url
    # Alembic uses a synchronous driver.
    return url.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg").replace(
        "postgresql+psycopg_async", "postgresql+psycopg"
    )


def render_item(type_, obj, autogen_context) -> str | bool:  # noqa: ANN001
    """Render StrEnumType as the plain VARCHAR it actually is.

    The custom type only coerces values in Python; the stored column is a
    VARCHAR. Rendering it literally would make every migration import
    application code, which couples the schema history to the codebase and
    breaks as soon as the type moves.
    """
    from app.database.base import StrEnumType

    if type_ == "type" and isinstance(obj, StrEnumType):
        autogen_context.imports.add("import sqlalchemy as sa")
        return f"sa.String(length={obj.impl.length})"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = database_url()
    connectable = engine_from_config(
        configuration, prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            # Batch mode so SQLite can alter tables.
            render_as_batch=True,
            render_item=render_item,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
