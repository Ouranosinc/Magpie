#!/usr/bin/env python
# -*- coding: utf-8 -*-
import inspect
import logging
import time
import warnings
from typing import TYPE_CHECKING

import alembic
import alembic.command
import alembic.config
import six
import transaction
from pyramid.settings import asbool
from sqlalchemy import engine_from_config
from sqlalchemy import exc as sa_exc
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.orm import configure_mappers, scoped_session
from sqlalchemy.orm.session import Session, sessionmaker
from zope.sqlalchemy import register
from zope.sqlalchemy.datamanager import join_transaction

from magpie.constants import get_constant
from magpie.utils import get_logger, get_settings, get_settings_from_config_ini, print_log, raise_log

# import or define all models here to ensure they are attached to the
# Base.metadata prior to any initialization routines
from magpie import models  # isort:skip # noqa: E402

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Optional, Union

    from pyramid.request import Request
    from sqlalchemy.engine.base import Engine

    from magpie.typedefs import AnySettingsContainer, SettingsType, Str


LOGGER = get_logger(__name__)

# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()


def get_db_url(username=None,   # type: Optional[Str]
               password=None,   # type: Optional[Str]
               db_host=None,    # type: Optional[Str]
               db_port=None,    # type: Optional[Union[Str,int]]
               db_name=None,    # type: Optional[Str]
               settings=None,   # type: AnySettingsContainer
               ):               # type: (...) -> Str
    """
    Retrieve the database connection URL with provided settings.
    """
    db_url = get_constant("MAGPIE_DB_URL", settings, raise_missing=False, print_missing=True, raise_not_set=False)
    if db_url:
        LOGGER.info("Using setting 'MAGPIE_DB_URL' for database connection.")
    else:
        def _get(param, names):
            if param is not None:
                return param
            if isinstance(names, six.string_types):
                names = [names]
            default = get_constant("MAGPIE_POSTGRES_{}".format(names[0].upper()), {}, raise_not_set=False)
            for prefixes in [("MAGPIE_POSTGRES_", "magpie.postgres_"), ("POSTGRES_", "postgres.")]:
                for kw in names:
                    kw_envvar = "{}{}".format(prefixes[0], kw.upper())
                    kw_setting = "{}{}".format(prefixes[1], kw.lower())
                    param = get_constant(kw_envvar, settings, kw_setting, raise_missing=False, raise_not_set=False)
                    if param not in (None, default):
                        return param
            return default

        db_url = "postgresql://%s:%s@%s:%s/%s" % (
            _get(username, ["username", "user"]),
            _get(password, "password"),
            _get(db_host, "host"),
            _get(db_port, "port"),
            _get(db_name, ["db", "database"]),
        )
        LOGGER.info("Using composed settings 'MAGPIE_POSTGRES_<>' for database connection.")
    LOGGER.debug("Resolved database connection URL: [%s]", db_url)
    return db_url


def get_engine(container=None, prefix="sqlalchemy.", **kwargs):
    # type: (Optional[AnySettingsContainer], Str, Any) -> Engine
    settings = get_settings(container or {})
    settings[prefix + "url"] = get_db_url(settings=settings)
    settings.setdefault(prefix + "pool_pre_ping", True)
    kwargs = kwargs or {}
    kwargs["convert_unicode"] = True
    return engine_from_config(settings, prefix, **kwargs)


def get_session_factory(engine):
    """
    Create a new session with integrated thread-local scope for safe handling across application workers.
    """
    session_factory = sessionmaker(bind=engine)
    return scoped_session(session_factory)


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


def get_session_from_other(db_session):
    return get_session_factory(db_session.bind)


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


def get_connected_session(request):
    # type: (Request) -> Session
    """
    Retrieve the session attached to the request or recreated it to ensure it is open and within scoped transaction.
    """
    # This is the only session reference we can trust to be fresh because it is
    # forcefully generated for each request, regardless if any caching took place.
    db_session = request.db

    # If the session connection or transaction was closed somehow by incorrectly passed around reference
    # (concurrent request), reconnect with new scoped session.
    if not db_session.is_active:
        LOGGER.debug("Session [%s] was inactive, creating new scoped session for resource.", db_session)
        db_session = get_session_from_other(db_session)
        LOGGER.debug("Session [%s] created.", db_session)

    # no-op if already joined, but make sure to initiate if no transaction when session reestablished from cache
    join_transaction(db_session)
    return db_session


def run_database_migration(container=None, db_session=None):
    # type: (Optional[AnySettingsContainer], Optional[Session]) -> None
    """
    Runs database migration operations with :mod:`alembic`, using the provided session or a new engine connection.
    """
    ini_file = get_constant("MAGPIE_INI_FILE_PATH", container)
    LOGGER.info("Using file '%s' for migration.", ini_file)
    alembic_args = ["-c", ini_file, "upgrade", "heads"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=sa_exc.SAWarning)
        if not isinstance(db_session, Session):
            alembic.config.main(argv=alembic_args)
        else:
            engine = db_session.bind
            with engine.begin() as connection:
                alembic_cfg = alembic.config.Config(file_=ini_file)
                alembic_cfg.attributes["connection"] = connection   # pylint: disable=E1137
                alembic.command.upgrade(alembic_cfg, "head")


def get_database_revision(db_session):
    # type: (Session) -> Str
    """
    Obtains the database revision number employed by :mod:`alembic` for schema migration.
    """
    query = "SELECT version_num FROM alembic_version"
    result = db_session.execute(query).fetchone()
    return result["version_num"]


def is_database_ready(db_session=None, container=None):
    # type: (Optional[Session], Optional[AnySettingsContainer]) -> bool
    """
    Obtains the database status against expected table names to ensure it is ready for use.
    """
    if isinstance(db_session, Session):
        engine = db_session.bind
    else:
        engine = get_engine(container=container)
    inspector = Inspector.from_engine(engine)
    table_names = inspector.get_table_names()

    for _, obj in inspect.getmembers(models):
        if inspect.isclass(obj) and hasattr(obj, "__tablename__"):
            if obj.__tablename__ not in table_names:
                print_log("Database table (or its associated parent) is missing for '{}' object".format(obj),
                          logger=LOGGER, level=logging.ERROR)
                return False
    return True


def run_database_migration_when_ready(settings, db_session=None):
    # type: (SettingsType, Optional[Session]) -> None
    """
    Runs db migration if requested by config and need from revisions.
    """
    db_ready = False
    if asbool(get_constant("MAGPIE_DB_MIGRATION", settings, "magpie.db_migration",
                           default_value=True, raise_missing=False, raise_not_set=False, print_missing=True)):
        conf_attempts = int(get_constant("MAGPIE_DB_MIGRATION_ATTEMPTS", settings, "magpie.db_migration_attempts",
                                         default_value=5, raise_missing=False, raise_not_set=False, print_missing=True))

        print_log("Running database migration (as required)...", logger=LOGGER)
        attempts = max(conf_attempts, 1)
        if attempts != conf_attempts:
            print_log("Database migration attempts updated to {}".format(attempts),
                      logger=LOGGER, level=logging.WARNING)
        for i in range(1, attempts + 1):
            try:
                run_database_migration(db_session=db_session, container=settings)
            except ImportError as exc:
                print_log("Database migration produced [{!r}] (ignored).".format(exc),
                          logger=LOGGER, level=logging.WARNING, exc_info=exc)
            except Exception as exc:
                if i <= attempts:
                    print_log("Database migration failed [{!r}]. Retrying... ({}/{})".format(exc, i, attempts),
                              logger=LOGGER, level=logging.WARNING, exc_info=exc)
                    time.sleep(2)
                    continue
                raise_log("Database migration failed [{!r}]".format(exc), exception=RuntimeError, logger=LOGGER)

            db_ready = is_database_ready(db_session=db_session, container=settings)
            if not db_ready:
                if i <= attempts:
                    print_log("Database not ready. Retrying... ({}/{})".format(i, attempts),
                              logger=LOGGER, level=logging.WARNING)
                    time.sleep(2)
                    continue
                print_log("Database not ready. Maximum attempts reached ({})".format(attempts),
                          logger=LOGGER, level=logging.WARNING)
            break
    else:
        print_log("Database migration skipped as per 'MAGPIE_DB_MIGRATION' requirement...", logger=LOGGER)
        db_ready = is_database_ready(db_session=db_session, container=settings)
    if not db_ready:
        raise_log("Database not ready", exception=RuntimeError, logger=LOGGER)


def set_sqlalchemy_log_level(magpie_log_level):
    # type: (Union[Str, int]) -> SettingsType
    """
    Suppresses :py:mod:`sqlalchemy` verbose logging if not in ``logging.DEBUG`` for Magpie.
    """
    if isinstance(magpie_log_level, six.string_types):
        magpie_log_level = logging.getLevelName(magpie_log_level)
    sa_settings = {"sqlalchemy.echo": True}
    if magpie_log_level > logging.DEBUG:
        sa_settings["sqlalchemy.echo"] = False
        sa_loggers = "sqlalchemy.engine.base.Engine".split(".")
        sa_log = logging.getLogger(sa_loggers[0])
        sa_log.setLevel(logging.WARN)   # WARN to avoid INFO logs which are too verbose
        for h in sa_log.handlers:
            sa_log.removeHandler(h)
        for sa_mod in sa_loggers[1:]:
            sa_log = sa_log.getChild(sa_mod)
            sa_log.setLevel(logging.WARN)
    return sa_settings


def includeme(config):
    LOGGER.info("Adding DB session...")

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
