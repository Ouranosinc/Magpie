from __future__ import with_statement
from alembic import context
from logging.config import fileConfig
from sqlalchemy.schema import MetaData
# noinspection PyProtectedMember
from sqlalchemy.engine import create_engine, Connection
from sqlalchemy.exc import OperationalError
from magpie.db import get_db_url
from magpie.constants import get_constant


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# verify if a connection is already provided
config_connection = None
if 'connection' in config.attributes and isinstance(config.attributes['connection'], Connection):
    config_connection = context.config.attributes['connection']

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)

# add your model's MetaData object here
target_metadata = MetaData(naming_convention={
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
})


# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline():
    """Run migrations in 'offline' mode.

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


def run_migrations_connection(connection):
    # type: (Connection) -> None
    """Run migrations in 'online' mode with provided connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table='alembic_version',
        transaction_per_migration=True,
        render_as_batch=True
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    # test the connection, if database is missing try creating it
    url = get_db_url()
    try:
        connectable = create_engine(url)
        with connectable.connect():
            pass
    except OperationalError as ex:
        # see for details:
        #   https://stackoverflow.com/questions/6506578
        db_name = get_constant('MAGPIE_POSTGRES_DB')
        if 'database "{}" does not exist'.format(db_name) not in str(ex):
            raise   # any error is OperationalError, so validate only missing db error
        db_default_postgres_url = get_db_url(
            username='postgres',    # only postgres user can connect to default 'postgres' db
            password='',
            db_host=get_constant('MAGPIE_POSTGRES_HOST'),
            db_port=get_constant('MAGPIE_POSTGRES_PORT'),
            db_name='postgres'
        )
        connectable = create_engine(db_default_postgres_url)
        with connectable.connect() as connection:
            connection.execute("commit")    # end initial transaction
            connection.execute("create database {}".format(db_name))

    # retry connection and run migration
    with connectable.connect() as connection:
        try:
            run_migrations_connection(connection)
        finally:
            connection.close()


if context.is_offline_mode():
    run_migrations_offline()
elif config_connection is None:
    run_migrations_online()
else:
    run_migrations_connection(config_connection)
