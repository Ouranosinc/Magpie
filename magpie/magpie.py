#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations
"""

# -- Standard library --------------------------------------------------------
import logging.config
import argparse
import os
import logging
LOGGER = logging.getLogger(__name__)

# -- Ziggurat_foundation ----
from ziggurat_foundations.models import groupfinder

# -- Pyramid ----
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import SignedCookieSessionFactory

# -- Project specific --------------------------------------------------------
from __meta__ import __version__ as __ver__
from __init__ import *
from db import postgresdb
import models
THIS_DIR = os.path.dirname(__file__)


@view_config(route_name='version')
def get_version(request):
    version = __ver__
    return HTTPOk(
        body=json.dumps({'version': version}),
        content_type='application/json'
    )


def init_anonymous():
    db = postgresdb()
    if not GroupService.by_group_name(ANONYMOUS_USER, db_session=db):
        anonymous_group = models.Group(group_name=ANONYMOUS_USER)
        db.add(anonymous_group)
        db.commit()

        anonymous_user = models.User(user_name=ANONYMOUS_USER, email=ANONYMOUS_USER+'@mail.com')
        db.add(anonymous_user)
        db.commit()

        group_entry = models.UserGroup(group_id=anonymous_group.id, user_id=anonymous_user.id)
        db.add(group_entry)
        db.commit()
    else:
        LOGGER.debug('anonymous already initialized')


def init_admin():
    db = postgresdb()
    if not GroupService.by_group_name(ADMIN_GROUP, db_session=db):
        admin_group = models.Group(group_name=ADMIN_GROUP)
        db.add(admin_group)
        db.commit()

        admin_user = models.User(user_name=ADMIN_USER, email='')
        admin_user.set_password(ADMIN_PASSWORD)
        admin_user.regenerate_security_code()
        db.add(admin_user)
        db.commit()

        group = GroupService.by_group_name(ADMIN_GROUP, db_session=db)
        group_entry = models.UserGroup(group_id=group.id, user_id=admin_user.id)
        db.add(group_entry)
        db.commit()

        new_group_permission = models.GroupPermission(perm_name=ADMIN_PERM, group_id=group.id)
        db.add(new_group_permission)
        db.commit()
    else:
        LOGGER.debug('admin already initialized')


def main(global_config, **settings):
    """
    This function returns a Pyramid WSGI application.
    """
    # Initialize database with default user: admin+anonymous
    init_admin()
    init_anonymous()

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
    config.include('login')
    config.include('home')
    config.include('db')
    config.include('management')

    config.add_route('version', '/version')
    config.scan('magpie')

    config.set_default_permission(ADMIN_PERM)
    return config.make_wsgi_app()


if __name__ == '__main__':
    main()

