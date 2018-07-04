#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations
"""

# -- Standard library --403------------------------------------------------------
import logging.config
import argparse
import os
import time
import logging
LOGGER = logging.getLogger(__name__)

# -- Definitions
from definitions.alembic_definitions import *
from definitions.pyramid_definitions import *
from definitions.sqlalchemy_definitions import *
from definitions.ziggurat_definitions import *

# -- Project specific --------------------------------------------------------
from __init__ import *
from api.api_except import *
from api.api_rest_schemas import *
from common import *
from helpers.register_default_users import register_default_users
from helpers.register_providers import magpie_register_services_from_config
import models
import db
import __meta__
MAGPIE_MODULE_DIR = os.path.abspath(os.path.dirname(__file__))
MAGPIE_ROOT = os.path.dirname(MAGPIE_MODULE_DIR)
sys.path.insert(0, MAGPIE_MODULE_DIR)


@VersionAPI.get(tags=[APITag], api_security=SecurityEveryoneAPI, response_schemas={
    '200': Version_GET_OkResponseSchema()
})
@view_config(route_name='version', request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_version(request):
    return valid_http(httpSuccess=HTTPOk,
                      content={u'version': __meta__.__version__, u'db_version': db.get_database_revision(request.db)},
                      detail=Version_GET_OkResponseSchema.description, contentType='application/json')


#@NotFoundAPI.get(schema=NotFoundResponseSchema(), response_schemas={
#    '404': NotFoundResponseSchema(description="Route not found")})
@notfound_view_config()
def not_found(request):
    content = get_request_info(request, default_msg="The route resource could not be found.")
    return raise_http(nothrow=True, httpError=HTTPNotFound, contentType='application/json',
                      detail=content['detail'], content=content)


@exception_view_config()
def internal_server_error(request):
    content = get_request_info(request, default_msg=InternalServerErrorResponseSchema.description)
    return raise_http(nothrow=True, httpError=HTTPInternalServerError, contentType='application/json',
                      detail=content['detail'], content=content)


@forbidden_view_config()
def unauthorized_access(request):
    # if not overridden, default is HTTPForbidden [403], which is for a slightly different situation
    # this better reflects the HTTPUnauthorized [401] user access with specified AuthZ headers
    # [http://www.restapitutorial.com/httpstatuscodes.html]
    content = get_request_info(request, default_msg=UnauthorizedResponseSchema.description)
    return raise_http(nothrow=True, httpError=HTTPUnauthorized, contentType='application/json',
                      detail=content['detail'], content=content)


def get_request_info(request, default_msg="undefined"):
    content = {u'route_name': str(request.upath_info), u'request_url': str(request.url), u'detail': default_msg}
    if hasattr(request, 'exception'):
        if hasattr(request.exception, 'json'):
            if type(request.exception.json) is dict:
                content.update(request.exception.json)
    elif hasattr(request, 'matchdict'):
        if request.matchdict is not None and request.matchdict != '':
            content.update(request.matchdict)
    return content


def main(global_config=None, **settings):
    """
    This function returns a Pyramid WSGI application.
    """

    settings['magpie.root'] = MAGPIE_ROOT
    settings['magpie.module'] = MAGPIE_MODULE_DIR

    # migrate db as required and check if database is ready
    print_log('Running database migration (as required) ...')
    try:
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
    providers_config_path = '{}/providers.cfg'.format(MAGPIE_ROOT)
    magpie_ini_path = '{}/magpie.ini'.format(MAGPIE_MODULE_DIR)
    svc_db_session = db.get_db_session_from_config_ini(magpie_ini_path)
    magpie_register_services_from_config(providers_config_path, push_to_phoenix=settings['magpie.phoenix_push'],
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

    magpie_secret = os.getenv('MAGPIE_SECRET')
    if magpie_secret is None:
        print_log('Use default secret from magpie.ini', level=logging.DEBUG)
        magpie_secret = settings['magpie.secret']

    authn_policy = AuthTktAuthenticationPolicy(
        magpie_secret,
        callback=groupfinder,
    )
    authz_policy = ACLAuthorizationPolicy()

    config = Configurator(
        settings=settings,
        root_factory=models.RootFactory,
        authentication_policy=authn_policy,
        authorization_policy=authz_policy
    )

    config.include('magpie')

    # include api views
    magpie_api_path = '{}/__api__'.format(settings['magpie.url'])
    magpie_api_view = '{}/api-explorer'.format(settings['magpie.url'])
    config.cornice_enable_openapi_view(
        api_path=magpie_api_path,
        title=TitleAPI,
        description="OpenAPI documentation",
        version=__meta__.__version__
    )
    config.cornice_enable_openapi_explorer(api_explorer_path=magpie_api_view)
    #config.register_swagger_ui(swagger_ui_path=magpie_api_path)

    # generate the api specs from code definitions
    api_json = api_spec(use_docstring_summary=True)
    api_json_file_path = '{}/ui/swagger-ui/magpie-rest-api.json'.format(MAGPIE_MODULE_DIR)
    with open(api_json_file_path, 'w') as api_file:
        api_file.write(repr(api_json))

    config.scan('magpie')
    config.set_default_permission(ADMIN_PERM)

    wsgi_app = config.make_wsgi_app()
    return wsgi_app


if __name__ == '__main__':
    main()
