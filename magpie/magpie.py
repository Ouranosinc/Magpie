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
from pyramid.view import view_config, notfound_view_config, exception_view_config
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.config import Configurator

# -- Project specific --------------------------------------------------------
from __meta__ import __version__
from __init__ import *
#from db import postgresdb
from api_except import *
import models
import db
THIS_DIR = os.path.dirname(__file__)
sys.path.insert(0, THIS_DIR)


@view_config(route_name='version', permission=NO_PERMISSION_REQUIRED)
def get_version(request):
    return valid_http(httpSuccess=HTTPOk,
                      content={u'version': __version__, u'db_version': db.get_database_revision(request.db)},
                      detail="Get version successful", contentType='application/json')


@notfound_view_config()
def not_found(request):
    content = get_request_info(request, default_msg="The route resource could not be found")
    return raise_http(nothrow=True, httpError=HTTPNotFound, contentType='application/json',
                      detail=content['detail'], content=content)


@exception_view_config()
def internal_server_error(request):
    content = get_request_info(request, default_msg="Internal Server Error. Unhandled exception occurred")
    return raise_http(nothrow=True, httpError=HTTPInternalServerError, contentType='application/json',
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
    try:
        db.run_database_migration()
    except Exception as e:
        raise Exception('Database migration failed [{}]'.format(str(e)))
    if not db.is_database_ready():
        time.sleep(2)
        raise Exception('Database not ready')

    hostname = os.getenv('HOSTNAME')
    if hostname:
        settings['magpie.url'] = 'http://{hostname}:{port}/magpie'.format(hostname=hostname, port=settings['magpie.port'])

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

    return config.make_wsgi_app()


if __name__ == '__main__':
    main()
