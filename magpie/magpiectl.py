#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations
"""

# -- Project specific --------------------------------------------------------
from magpie.common import print_log, raise_log, str2bool
from magpie.constants import get_constant
from magpie.definitions.sqlalchemy_definitions import *
from magpie.helpers.register_default_users import register_default_users
from magpie.register import (
    magpie_register_services_from_config,
    magpie_register_permissions_from_config,
)
from magpie.security import auth_config_from_settings
from magpie import db, constants

# -- Standard library --------------------------------------------------------
import time
import warnings
# noinspection PyUnresolvedReferences
import logging
import logging.config   # find config in 'logging.ini'
LOGGER = logging.getLogger(__name__)


# noinspection PyUnusedLocal
def main(global_config=None, **settings):
    """
    This function returns a Pyramid WSGI application.
    """
    settings['magpie.root'] = constants.MAGPIE_ROOT
    settings['magpie.module'] = constants.MAGPIE_MODULE_DIR

    # suppress sqlalchemy logging if not in debug for magpie
    log_lvl = get_constant('MAGPIE_LOG_LEVEL', settings, 'magpie.log_level', default_value=logging.INFO,
                           raise_missing=False, print_missing=False, raise_not_set=False)
    log_lvl = logging.getLevelName(log_lvl) if isinstance(log_lvl, int) else log_lvl
    if log_lvl.upper() != 'DEBUG':
        sa_log = logging.getLogger('sqlalchemy.engine.base.Engine')
        sa_log.setLevel(logging.WARN)   # WARN to avoid INFO logs
    LOGGER.setLevel(log_lvl)

    # migrate db as required and check if database is ready
    if get_constant('MAGPIE_DB_MIGRATION', settings, 'magpie.db_migration', True,
                    raise_missing=False, raise_not_set=False, print_missing=True):
        print_log('Running database migration (as required) ...')
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=sa_exc.SAWarning)
                db.run_database_migration()
        except ImportError:
            pass
        except Exception as e:
            raise_log('Database migration failed [{}]'.format(str(e)), exception=RuntimeError)
    if not db.is_database_ready():
        time.sleep(2)
        raise_log('Database not ready')

    print_log('Register default users...')
    register_default_users()

    print_log('Register configuration providers...', LOGGER)
    db_session = db.get_db_session_from_config_ini(constants.MAGPIE_INI_FILE_PATH)
    push_phoenix = str2bool(get_constant('PHOENIX_PUSH', settings=settings, settings_name='magpie.phoenix_push',
                                         raise_missing=False, raise_not_set=False, print_missing=True))
    magpie_register_services_from_config(constants.MAGPIE_PROVIDERS_CONFIG_PATH, push_to_phoenix=push_phoenix,
                                         force_update=True, disable_getcapabilities=False, db_session=db_session)

    print_log('Register configuration permissions...', LOGGER)
    magpie_register_permissions_from_config(constants.MAGPIE_PERMISSIONS_CONFIG_PATH, db_session=db_session)

    print_log('Running configurations setup...')
    magpie_url_template = 'http://{hostname}:{port}'
    port = get_constant('MAGPIE_PORT', settings=settings, settings_name='magpie.port')
    if port:
        settings['magpie.port'] = port
    hostname = get_constant('HOSTNAME')
    if hostname:
        settings['magpie.url'] = magpie_url_template.format(hostname=hostname, port=settings['magpie.port'])

    # avoid cornice conflicting with magpie exception views
    settings['handle_exceptions'] = False

    config = auth_config_from_settings(settings)
    config.include('magpie')
    # Don't use scan otherwise modules like 'magpie.adapter' are
    # automatically found and cause import errors on missing packages
    # config.scan('magpie')
    config.set_default_permission(get_constant('MAGPIE_ADMIN_PERMISSION'))

    print_log('Starting Magpie app...')
    wsgi_app = config.make_wsgi_app()
    return wsgi_app


if __name__ == '__main__':
    main()
