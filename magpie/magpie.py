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

# -- Ziggurat_foundation ----
from ziggurat_foundations.models import groupfinder

# -- Pyramid ----
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import SignedCookieSessionFactory
from pyramid.view import *
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.config import Configurator

# -- Cornice (display swagger REST API docs)
import colander
from cornice import Service
from cornice.service import get_services
from cornice.validators import colander_body_validator
from cornice_swagger.swagger import CorniceSwagger
#from flask import Flask, jsonify
#from flasgger import Swagger
from server import DirectoryServer
from threading import Thread

# -- Project specific --------------------------------------------------------
from __meta__ import __version__
from __init__ import *
#from db import postgresdb
THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, THIS_DIR)
from api_except import *
import models
import db


@view_config(route_name='version', permission=NO_PERMISSION_REQUIRED)
def get_version(request):
    return valid_http(httpSuccess=HTTPOk,
                      content={u'version': __version__, u'db_version': db.get_database_revision(request.db)},
                      detail="Get version successful", contentType='application/json')


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


api_users = Service(name='Users', path='/users/{user}', description="Cornice Demo")
def UserAPI(object):
    @api_users.get(tags=['users'])
    def get_value(request):
        return {u'username': u'dummy'}


api_swagger = Service(name='Magpie REST API', path='__api__', description="Magpie REST API documentation")
@api_swagger.get()
def openapi_spec(request):
    my_generator = CorniceSwagger(get_services())
    my_spec = my_generator('Magpie REST API', '0.5.x')
    return my_spec


class CorniceSwaggerPredicate(object):
    """Predicate to add simple information to Cornice Swagger."""

    def __init__(self, schema, config):
        self.schema = schema

    def phash(self):
        return str(self.schema)

    def __call__(self, context, request):
        return self.schema


def api_docs_server(**settings):
    api_server = DirectoryServer(settings['magpie.api.dir'], settings['magpie.api.port'])
    api_server.serve_forever()


def main(global_config=None, **settings):
    """
    This function returns a Pyramid WSGI application.
    """

    # migrate db as required and check if database is ready
    try:
        db.run_database_migration()
    except ImportError:
        pass
    except Exception as e:
        raise Exception('Database migration failed [{}]'.format(str(e)))
    if not db.is_database_ready():
        time.sleep(2)
        raise Exception('Database not ready')

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

    # include api views
    magpie_api_path = '{}/__api__'.format(settings['magpie.url'])
    magpie_api_view = '{}/api-explorer'.format(settings['magpie.url'])
    print(magpie_api_path)
    print(magpie_api_view)
    config.include('cornice')
    config.include('cornice_swagger')
    config.cornice_enable_openapi_view(
        api_path=magpie_api_path,
        title='Magpie REST API',
        description="OpenAPI documentation",
        version='1.0.0'
    )
    config.cornice_enable_openapi_explorer(api_explorer_path=magpie_api_view)
    #config.register_swagger_ui(swagger_ui_path=magpie_api_path)

    # include magpie components (all the file which define includeme)
    config.include('pyramid_chameleon')
    config.include('pyramid_mako')
    config.include('login')
    config.include('home')
    config.include('db')
    config.include('management')
    config.include('ui')

    config.add_route('version', '/version')
    config.scan('magpie')

    config.set_default_permission(ADMIN_PERM)

    # app = Flask(__name__)
    # swagger = Swagger(app)
    # app.run(port='2003')

    #api_handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    #api_server = SocketServer.TCPServer(("", int(settings['magpie.api.port'])), api_handler)
    #api_server.serve_forever()

    settings['magpie.api.url'] = magpie_url_template.format(hostname=hostname, port=settings['magpie.api.port'])
    settings['magpie.api.dir'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'api'))
    print(settings['magpie.api.dir'])
    api_thread = Thread(target=api_docs_server, kwargs=settings)
    api_thread.start()

    wsgi_app = config.make_wsgi_app()
    return wsgi_app


if __name__ == '__main__':
    main()
