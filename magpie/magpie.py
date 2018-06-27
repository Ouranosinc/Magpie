#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations
"""

# -- Standard library --------------------------------------------------------
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
import models
import db
import __meta__
THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, THIS_DIR)


@VersionAPI.get(schema=Version_GET_Schema(), tags=[APITag], response_schemas={
    '200': Version_GET_OkResponseSchema(description="Get version successful.")})
@view_config(route_name='version', request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_version(request):
    return valid_http(httpSuccess=HTTPOk,
                      content={u'version': __meta__.__version__, u'db_version': db.get_database_revision(request.db)},
                      detail="Get version successful.", contentType='application/json')


#@NotFoundAPI.get(schema=NotFoundResponseSchema(), response_schemas={
#    '404': NotFoundResponseSchema(description="Route not found")})
@notfound_view_config()
def not_found(request):
    content = get_request_info(request, default_msg="The route resource could not be found.")
    return raise_http(nothrow=True, httpError=HTTPNotFound, contentType='application/json',
                      detail=content['detail'], content=content)


@exception_view_config()
def internal_server_error(request):
    content = get_request_info(request, default_msg="Internal Server Error. Unhandled exception occurred.")
    return raise_http(nothrow=True, httpError=HTTPInternalServerError, contentType='application/json',
                      detail=content['detail'], content=content)


@forbidden_view_config()
def unauthorized_access(request):
    # if not overridden, default is HTTPForbidden [403], which is for a slightly different situation
    # this better reflects the HTTPUnauthorized [401] user access with specified AuthZ headers
    # [http://www.restapitutorial.com/httpstatuscodes.html]
    msg = "Unauthorized. Insufficient user privileges or missing authentication headers."
    content = get_request_info(request, default_msg=msg)
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

    # migrate db as required and check if database is ready
    LOGGER.info('Running database migration (as required) ...')
    try:
        db.run_database_migration()
    except ImportError:
        pass
    except Exception as e:
        raise Exception('Database migration failed [{}]'.format(str(e)))
    if not db.is_database_ready():
        time.sleep(2)
        raise Exception('Database not ready')

    LOGGER.info('Running configurations setup...')
    magpie_url_template = 'http://{hostname}:{port}/magpie'
    hostname = os.getenv('HOSTNAME')
    if hostname:
        settings['magpie.url'] = magpie_url_template.format(hostname=hostname, port=settings['magpie.port'])

    magpie_secret = os.getenv('MAGPIE_SECRET')
    if magpie_secret is None:
        LOGGER.debug('Use default secret from magpie.ini')
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
        title='Magpie REST API',
        description="OpenAPI documentation",
        version=__meta__.__version__
    )
    config.cornice_enable_openapi_explorer(api_explorer_path=magpie_api_view)
    #config.register_swagger_ui(swagger_ui_path=magpie_api_path)

    config.scan('magpie')
    config.set_default_permission(ADMIN_PERM)

    wsgi_app = config.make_wsgi_app()
    return wsgi_app


if __name__ == '__main__':
    main()
