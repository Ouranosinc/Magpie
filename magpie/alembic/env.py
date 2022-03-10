from __future__ import with_statement

import os
from typing import TYPE_CHECKING

from alembic import context  # noqa: F403
from sqlalchemy.engine import Connectable, Connection, create_engine  # noqa: W0212
from sqlalchemy.schema import MetaData
from sqlalchemy_utils import create_database, database_exists

from magpie.constants import get_constant
from magpie.db import get_db_url
from magpie.utils import get_logger, get_settings_from_config_ini

if TYPE_CHECKING:
    from typing import Optional, Union

LOGGER = get_logger(__name__)


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# verify if a connection is already provided
CONFIG_CONNECTION = None
if "connection" in config.attributes and isinstance(config.attributes["connection"], Connection):
    CONFIG_CONNECTION = context.config.attributes["connection"]

# add your model's MetaData object here
target_metadata = MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})


def run_migrations_offline():
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DB-API to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_db_url()
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online(connection=None):
    # type: (Optional[Union[Connection, Connection]]) -> None
    """
    Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a connection with the context.
    """
    if not CONFIG_CONNECTION:
        ini = get_constant("MAGPIE_INI_FILE_PATH", raise_not_set=False, raise_missing=False, print_missing=True)
        settings = None
        if ini and os.path.isfile(ini):
            settings = get_settings_from_config_ini(ini)
        url = get_db_url(settings=settings)
    else:
        url = CONFIG_CONNECTION.engine.url

    def connect(_connection=None):
        # type: (Optional[Union[Connection, Connection]]) -> Connection
        if isinstance(_connection, Connection) and not _connection.closed:
            return _connection
        if not isinstance(_connection, Connectable):
            _connection = create_engine(url, convert_unicode=True, echo=False)
        return _connection.connect()

    if not database_exists(url):
        db_name = get_constant("MAGPIE_POSTGRES_DB")
        LOGGER.warning("Database [%s] not found, attempting creation...", db_name)
        create_database(url, encoding="utf8", template="template0")
        connection = create_engine(url, convert_unicode=True, echo=False)

        # retry connection and run migration
    with connect(connection) as migrate_conn:
        try:
            context.configure(
                connection=migrate_conn,
                target_metadata=target_metadata,
                version_table="alembic_version",
                transaction_per_migration=True,
                render_as_batch=True
            )
            with context.begin_transaction():
                context.run_migrations()
        finally:
            # close the connection only if not given argument
            if migrate_conn is not connection:
                migrate_conn.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online(CONFIG_CONNECTION)
