from sqlalchemy import engine_from_config
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import configure_mappers
from sqlalchemy.sql import select
from sqlalchemy.engine.reflection import Inspector
import inspect
import alembic.config
import zope.sqlalchemy
import os
from magpie import models
import logging
logger = logging.getLogger(__name__)


# import or define all models here to ensure they are attached to the
# Base.metadata prior to any initialization routines
from models import *

# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()


def get_engine(settings, prefix='sqlalchemy.'):
    database_url = 'postgresql://' \
                   + os.getenv('POSTGRES_USER', 'postgres') + \
                   ':' + os.getenv('POSTGRES_PASSWORD', 'postgres') + \
                   '@' + os.getenv('POSTGRES_HOST', 'localhost') + \
                   ':' + os.getenv('POSTGRES_PORT', '5432') + \
                   '/' + os.getenv('POSTGRES_DB', 'magpiedb')

    settings[prefix+'url'] = database_url
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
    dbsession = session_factory()
    zope.sqlalchemy.register(dbsession, transaction_manager=transaction_manager)
    return dbsession


def run_database_migration():
    curr_path = os.path.dirname(os.path.abspath(__file__))
    curr_path = os.path.dirname(curr_path)
    alembic_ini_path = '{path}/alembic.ini'.format(path=curr_path)
    alembic_args = ['-c', alembic_ini_path, 'upgrade', 'head']
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
    config.registry['dbsession_factory'] = session_factory

    # make request.dbsession available for use in Pyramid
    config.add_request_method(
        # r.tm is the transaction manager used by pyramid_tm
        lambda r: get_tm_session(session_factory, r.tm),
        'db',
        reify=True
    )
