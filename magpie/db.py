#!/usr/bin/python
# -*- coding: utf-8 -*-
from magpie.constants import MAGPIE_ROOT
from magpie.definitions.alembic_definitions import *
from magpie.definitions.sqlalchemy_definitions import *
from common import print_log
# noinspection PyCompatibility
import configparser
import transaction
import models
import inspect
import zope.sqlalchemy
import os
import logging
logger = logging.getLogger(__name__)

# import or define all models here to ensure they are attached to the
# Base.metadata prior to any initialization routines
from models import *

# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()


def get_db_url():
    return "postgresql://%s:%s@%s:%s/%s" % (
        os.getenv("POSTGRES_USER", "postgres"),
        os.getenv("POSTGRES_PASSWORD", "postgres"),
        os.getenv("POSTGRES_HOST", "localhost"),
        os.getenv("POSTGRES_PORT", "5432"),
        os.getenv("POSTGRES_DB", "magpiedb"),
    )


def get_engine(settings, prefix='sqlalchemy.'):
    settings[prefix+'url'] = get_db_url()
    return engine_from_config(settings, prefix)


def get_session_factory(engine):
    factory = sessionmaker()
    factory.configure(bind=engine)
    return factory


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
              dbsession = get_tm_session(session_factory, transaction.manager)

    """
    db_session = session_factory()
    zope.sqlalchemy.register(db_session, transaction_manager=transaction_manager)
    return db_session


def get_db_session_from_settings(settings):
    session_factory = get_session_factory(get_engine(settings))
    db_session = get_tm_session(session_factory, transaction)
    return db_session


def get_db_session_from_config_ini(config_ini_path, ini_main_section_name='app:magpie_app'):
    settings = get_settings_from_config_ini(config_ini_path, ini_main_section_name)
    return get_db_session_from_settings(settings)


def get_settings_from_config_ini(config_ini_path, ini_main_section_name='app:magpie_app'):
    parser = configparser.ConfigParser()
    parser.read([config_ini_path])
    settings = dict(parser.items(ini_main_section_name))
    return settings


def run_database_migration():
    alembic_args = ['-c', '{path}/alembic.ini'.format(path=MAGPIE_ROOT), 'upgrade', 'heads']
    alembic.config.main(argv=alembic_args)


def get_database_revision(db_session):
    s = select(['version_num'], from_obj='alembic_version')
    result = db_session.execute(s).fetchone()
    return result['version_num']


def is_database_ready():
    inspector = Inspector.from_engine(get_engine(dict()))
    table_names = inspector.get_table_names()

    for name, obj in inspect.getmembers(models):
        if inspect.isclass(obj):
            try:
                curr_table_name = obj.__tablename__
                if curr_table_name not in table_names:
                    return False
            except:
                continue
    return True


def includeme(config):
    """
    Initialize the model for a Pyramid app.

    Activate this setup using ``config.include('pyramid_blogr.models')``.

    """
    settings = config.get_settings()

    # use pyramid_tm to hook the transaction lifecycle to the request
    config.include('pyramid_tm')

    session_factory = get_session_factory(get_engine(settings))
    config.registry['db_session_factory'] = session_factory

    # make `request.db` available for use in Pyramid
    config.add_request_method(
        # r.tm is the transaction manager used by pyramid_tm
        lambda r: get_tm_session(session_factory, r.tm),
        'db',
        reify=True
    )
