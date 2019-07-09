#!/usr/bin/env python
# -*- coding: utf-8 -*-
from sqlalchemy.orm import scoped_session

from magpie.constants import get_constant
from magpie.definitions.alembic_definitions import alembic
from magpie.definitions.sqlalchemy_definitions import (
    register, sessionmaker, engine_from_config,
    configure_mappers, select, Inspector, Session, sa_exc
)
from magpie.definitions.pyramid_definitions import asbool
from magpie.utils import get_settings_from_config_ini, get_settings, print_log, raise_log, get_logger
from typing import TYPE_CHECKING
import transaction
import inspect
import warnings
import logging
import time

# import or define all models here to ensure they are attached to the
# Base.metadata prior to any initialization routines
from magpie import models

if TYPE_CHECKING:
    from magpie.definitions.typedefs import Any, AnySettingsContainer, SettingsType, Str, Optional, Union  # noqa: F401
    from magpie.definitions.sqlalchemy_definitions import Engine  # noqa: F401


LOGGER = get_logger(__name__)

# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()


def get_db_url(username=None, password=None, db_host=None, db_port=None, db_name=None, settings=None):
    return "postgresql://%s:%s@%s:%s/%s" % (
        username if username is not None else get_constant("MAGPIE_POSTGRES_USER", settings, "postgres.user"),
        password if password is not None else get_constant("MAGPIE_POSTGRES_PASSWORD", settings, "postgres.password"),
        db_host if db_host is not None else get_constant("MAGPIE_POSTGRES_HOST", settings, "postgres.host"),
        db_port if db_port is not None else get_constant("MAGPIE_POSTGRES_PORT", settings, "postgres.port"),
        db_name if db_name is not None else get_constant("MAGPIE_POSTGRES_DB", settings, "postgres.db"),
    )


def get_engine(container=None, prefix="sqlalchemy.", **kwargs):
    # type: (Optional[AnySettingsContainer], Str, Any) -> Engine
    settings = get_settings(container or {})
    settings[prefix + "url"] = get_db_url()
    settings.setdefault(prefix + "pool_pre_ping", True)
    kwargs = kwargs or {}
    kwargs["convert_unicode"] = True
    return engine_from_config(settings, prefix, **kwargs)


def get_session_factory(engine):
    return sessionmaker(bind=engine)


def get_tm_session(session_factory, transaction_manager):
    """
    Get a ``sqlalchemy.orm.Session`` instance backed by a transaction.

    This function will hook the session to the transaction manager which
    will take care of committing any changes.

    - When using pyramid_tm it will automatically be committed or aborted
      depending on whether an exception is raised.

    - When using scripts you should wrap the session in a manager yourself.
      For example::

          import transaction

          engine = get_engine(settings)
          session_factory = get_session_factory(engine)
          with transaction.manager:
              db_session = get_tm_session(session_factory, transaction.manager)

    """
    db_session = session_factory()
    register(db_session, transaction_manager=transaction_manager)
    return db_session


def get_db_session_from_settings(settings=None, **kwargs):
    # type: (Optional[AnySettingsContainer], Any) -> Session
    session_factory = get_session_factory(get_engine(settings, **kwargs))
    db_session = get_tm_session(session_factory, transaction.manager)
    return db_session


def get_db_session_from_config_ini(config_ini_path, ini_main_section_name="app:magpie_app", settings_override=None):
    settings = get_settings_from_config_ini(config_ini_path, ini_main_section_name)
    if isinstance(settings_override, dict):
        settings.update(settings_override)
    return get_db_session_from_settings(settings)


def run_database_migration(db_session=None):
    # type: (Optional[Session]) -> None
    """Runs db migration operations with alembic, using db session or a new engine connection."""
    ini_file = get_constant("MAGPIE_ALEMBIC_INI_FILE_PATH")
    LOGGER.info("Using file '{}' for migration.".format(ini_file))
    alembic_args = ["-c", ini_file, "upgrade", "heads"]
    if not isinstance(db_session, Session):
        alembic.config.main(argv=alembic_args)
    else:
        engine = db_session.bind
        with engine.begin() as connection:
            alembic_cfg = alembic.config.Config(file_=ini_file)
            alembic_cfg.attributes['connection'] = connection
            alembic.command.upgrade(alembic_cfg, "head")


def get_database_revision(db_session):
    # type: (Session) -> Str
    s = select(["version_num"], from_obj="alembic_version")
    result = db_session.execute(s).fetchone()
    return result["version_num"]


def is_database_ready(db_session=None):
    # type: (Optional[Session]) -> bool
    if isinstance(db_session, Session):
        engine = db_session.bind
    else:
        engine = get_engine(dict())
    inspector = Inspector.from_engine(engine)
    table_names = inspector.get_table_names()

    for _, obj in inspect.getmembers(models):
        if inspect.isclass(obj):
            # noinspection PyBroadException
            try:
                curr_table_name = obj.__tablename__
                if curr_table_name not in table_names:
                    return False
            except Exception:
                continue
    return True


def run_database_migration_when_ready(settings, db_session=None):
    # type: (SettingsType, Optional[Session]) -> None
    """
    Runs db migration if requested by config and need from revisions.
    """

    db_ready = False
    if asbool(get_constant("MAGPIE_DB_MIGRATION", settings, "magpie.db_migration",
                           default_value=True, raise_missing=False, raise_not_set=False, print_missing=True)):
        attempts = int(get_constant("MAGPIE_DB_MIGRATION_ATTEMPTS", settings, "magpie.db_migration_attempts",
                                    default_value=5, raise_missing=False, raise_not_set=False, print_missing=True))

        print_log("Running database migration (as required)...")
        attempts = max(attempts, 2)     # enforce at least 2 attempts, 1 for db creation and one for actual migration
        for i in range(1, attempts + 1):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", category=sa_exc.SAWarning)
                    run_database_migration(db_session)
            except ImportError as e:
                print_log("Database migration produced [{!r}] (ignored).".format(e), level=logging.WARNING)
                pass
            except Exception as e:
                if i <= attempts:
                    print_log("Database migration failed [{!r}]. Retrying... ({}/{})".format(e, i, attempts))
                    time.sleep(2)
                    continue
                else:
                    raise_log("Database migration failed [{!r}]".format(e), exception=RuntimeError)

            db_ready = is_database_ready(db_session)
            if not db_ready:
                print_log("Database not ready. Retrying... ({}/{})".format(i, attempts))
                time.sleep(2)
                continue
            break
    else:
        db_ready = is_database_ready(db_session)
    if not db_ready:
        time.sleep(2)
        raise_log("Database not ready", exception=RuntimeError)


def set_sqlalchemy_log_level(magpie_log_level):
    # type: (Union[Str, int]) -> SettingsType
    """Suppresses sqlalchemy logging if not in debug for magpie."""
    log_lvl = logging.getLevelName(magpie_log_level) if isinstance(magpie_log_level, int) else magpie_log_level
    sa_settings = {"sqlalchemy.echo": True}
    if log_lvl.upper() != "DEBUG":
        sa_settings["sqlalchemy.echo"] = False
        sa_loggers = "sqlalchemy.engine.base.Engine".split(".")
        sa_log = logging.getLogger(sa_loggers[0])
        sa_log.setLevel(logging.WARN)   # WARN to avoid INFO logs
        for h in sa_log.handlers:
            sa_log.removeHandler(h)
        for sa_mod in sa_loggers[1:]:
            sa_log = sa_log.getChild(sa_mod)
            sa_log.setLevel(logging.WARN)
    return sa_settings


def includeme(config):
    # use pyramid_tm to hook the transaction lifecycle to the request
    config.include("pyramid_tm")
    session_factory = get_session_factory(get_engine(config))
    config.registry["db_session_factory"] = session_factory

    # make `request.db` available for use in Pyramid
    config.add_request_method(
        # r.tm is the transaction manager used by pyramid_tm
        lambda r: get_tm_session(session_factory, r.tm),
        "db",
        reify=True
    )
