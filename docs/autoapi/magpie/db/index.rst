:mod:`magpie.db`
================

.. py:module:: magpie.db


Module Contents
---------------

.. data:: LOGGER
   

   

.. function:: get_db_url(username=None, password=None, db_host=None, db_port=None, db_name=None, settings=None)

.. function:: get_engine(container=None, prefix='sqlalchemy.', **kwargs) -> Engine

.. function:: get_session_factory(engine)

.. function:: get_tm_session(session_factory, transaction_manager)
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


.. function:: get_db_session_from_settings(settings=None, **kwargs) -> Session

.. function:: get_db_session_from_config_ini(config_ini_path, ini_main_section_name='app:magpie_app', settings_override=None)

.. function:: run_database_migration(db_session=None) -> None
   Runs db migration operations with alembic, using db session or a new engine connection.


.. function:: get_database_revision(db_session) -> Str

.. function:: is_database_ready(db_session=None) -> bool

.. function:: run_database_migration_when_ready(settings, db_session=None) -> None
   Runs db migration if requested by config and need from revisions.


.. function:: set_sqlalchemy_log_level(magpie_log_level) -> SettingsType
   Suppresses sqlalchemy logging if not in debug for magpie.


.. function:: includeme(config)

