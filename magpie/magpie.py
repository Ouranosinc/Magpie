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
import alembic.config
from sqlalchemy.sql import select
LOGGER = logging.getLogger(__name__)

# -- Ziggurat_foundation ----
from ziggurat_foundations.models import groupfinder

# -- Pyramid ----
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import SignedCookieSessionFactory
from pyramid.view import notfound_view_config

# -- Project specific --------------------------------------------------------
from __meta__ import __version__
from __init__ import *
#from db import postgresdb
import api_except
import models
THIS_DIR = os.path.dirname(__file__)


@view_config(route_name='version')
def get_version(request):
    return valid_http(httpSuccess=HTTPOk, content={u'version': __version__},
                      detail="Get version successful", contentType='application/json')


@notfound_view_config()
def not_found(request):
    content_type = 'application/json'
    content_json = format_content_json_str(HTTPNotFound.code, detail="The route resource could not be found.",
                                           contentType=content_type,
                                           content={u'route_name': str(request.upath_info),  u'url': str(request.url)})
    return generate_response_http_format(HTTPNotFound, jsonContent=content_json,
                                         httpKWArgs=None, outputType=content_type)


def init_db():
    curr_path = os.path.dirname(os.path.abspath(__file__))
    curr_path = os.path.dirname(curr_path)
    alembic_ini_path = curr_path+'/alembic.ini'
    alembic_args = ['-c'+alembic_ini_path, 'upgrade', 'heads']
    alembic.config.main(argv=alembic_args)


def get_database_revision(db_session):
    s = select(['version_num'], from_obj='alembic_version')
    result = db_session.execute(s).fetchone()
    return result['version_num']


def main(global_config=None, **settings):
    """
    This function returns a Pyramid WSGI application.
    """

    # Check is database is ready
    from db import is_database_ready
    if not is_database_ready():
        time.sleep(2)
        raise Exception('Database not ready')

    hostname = os.getenv('HOSTNAME')
    if hostname:
        settings['magpie.url'] = 'http://{hostname}:{port}/magpie'.format(hostname=hostname, port=settings['magpie.port'])

    from pyramid.config import Configurator

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
