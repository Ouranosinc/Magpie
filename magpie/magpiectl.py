#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations
"""

# -- Standard library --403------------------------------------------------------
import logging.config
import argparse
import time
import warnings
import logging
LOGGER = logging.getLogger(__name__)

# -- Definitions
from magpie.definitions.alembic_definitions import *
from magpie.definitions.pyramid_definitions import *
from magpie.definitions.sqlalchemy_definitions import *
from magpie.definitions.ziggurat_definitions import *

# -- Project specific --------------------------------------------------------
from __init__ import *
from magpie.api.api_except import *
from magpie.api.api_rest_schemas import *
from magpie.api.api_generic import *
from magpie.common import *
from magpie.helpers.register_default_users import register_default_users
from magpie.helpers.register_providers import magpie_register_services_from_config
from magpie.security import auth_config_from_settings
from magpie import models, db, __meta__


def main(global_config=None, **settings):
    """
    This function returns a Pyramid WSGI application.
    """

    settings['magpie.root'] = MAGPIE_ROOT
    settings['magpie.module'] = MAGPIE_MODULE_DIR

    # migrate db as required and check if database is ready
    if not settings.get('magpie.db_migration_disabled', False):
        print_log('Running database migration (as required) ...')
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=sa_exc.SAWarning)
                db.run_database_migration()
        except ImportError:
            pass
        except Exception as e:
            raise_log('Database migration failed [{}]'.format(str(e)))
    if not db.is_database_ready():
        time.sleep(2)
        raise_log('Database not ready')

    settings['magpie.phoenix_push'] = str2bool(os.getenv('PHOENIX_PUSH', False))

    print_log('Register default providers...', LOGGER)
    svc_db_session = db.get_db_session_from_config_ini(MAGPIE_INI_FILE_PATH)
    magpie_register_services_from_config(MAGPIE_PROVIDERS_CONFIG_PATH, push_to_phoenix=settings['magpie.phoenix_push'],
                                         force_update=True, disable_getcapabilities=False, db_session=svc_db_session)

    print_log('Register default users...')
    register_default_users()

    print_log('Running configurations setup...')
    magpie_url_template = 'http://{hostname}:{port}/magpie'
    port = os.getenv('MAGPIE_PORT')
    if port:
        settings['magpie.port'] = port
    hostname = os.getenv('HOSTNAME')
    if hostname:
        settings['magpie.url'] = magpie_url_template.format(hostname=hostname, port=settings['magpie.port'])

    # avoid cornice conflicting with magpie exception views
    settings['handle_exceptions'] = False

    config = auth_config_from_settings(settings)
    config.include('magpie')
    # Don't use scan otherwise modules like 'magpie.adapter' are
    # automatically found and cause import errors on missing packages
    #config.scan('magpie')
    config.set_default_permission(ADMIN_PERM)

    # include api views
    print_log('Running api documentation setup...')
    magpie_api_gen_disabled = os.getenv('MAGPIE_API_GENERATION_DISABLED')
    if magpie_api_gen_disabled:
        settings['magpie.api_generation_disabled'] = magpie_api_gen_disabled
    if 'magpie.api_generation_disabled' not in settings:
        settings['magpie.api_generation_disabled'] = False

    if not settings['magpie.api_generation_disabled']:
        magpie_api_path = '{base}{path}'.format(base=settings['magpie.url'], path=SwaggerGenerator.path)
        config.cornice_enable_openapi_view(
            api_path=magpie_api_path,
            title=TitleAPI,
            description=__meta__.__description__,
            version=__meta__.__version__
        )
        config.add_route(**service_api_route_info(SwaggerGenerator))
        config.add_view(api_schema, route_name=SwaggerGenerator.name, request_method='GET',
                        renderer='json', permission=NO_PERMISSION_REQUIRED)
        config.add_route(**service_api_route_info(SwaggerAPI))

    print_log('Starting Magpie app...')
    wsgi_app = config.make_wsgi_app()
    return wsgi_app


if __name__ == '__main__':
    main()
