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

# -- Project specific --------------------------------------------------------
from __meta__ import __version__ as __ver__
from __init__ import *
#from db import postgresdb
import models
THIS_DIR = os.path.dirname(__file__)


@view_config(route_name='version')
def get_version(request):
    version = __ver__
    return HTTPOk(
        body=json.dumps({'version': version}),
        content_type='application/json'
    )


def init_anonymous(db_session):
    db = db_session
    if not GroupService.by_group_name(ANONYMOUS_USER, db_session=db):
        anonymous_group = models.Group(group_name=ANONYMOUS_USER)
        db.add(anonymous_group)

    if not UserService.by_user_name(ANONYMOUS_USER, db_session=db):
        anonymous_user = models.User(user_name=ANONYMOUS_USER, email=ANONYMOUS_USER+'@mail.com')
        db.add(anonymous_user)

        group_id = GroupService.by_group_name(ANONYMOUS_USER, db_session=db).id
        user_id = UserService.by_user_name(ANONYMOUS_USER, db_session=db).id
        group_entry = models.UserGroup(group_id=group_id, user_id=user_id)
        db.add(group_entry)

    else:
        LOGGER.debug('anonymous already initialized')


def init_admin(db_session):
    db = db_session
    if not GroupService.by_group_name(ADMIN_GROUP, db_session=db):
        admin_group = models.Group(group_name=ADMIN_GROUP)
        db.add(admin_group)
        
    if not UserService.by_user_name(ADMIN_USER, db_session=db):
        admin_user = models.User(user_name=ADMIN_USER, email=ADMIN_USER+'@mail.com')
        admin_user.set_password(ADMIN_PASSWORD)
        admin_user.regenerate_security_code()
        db.add(admin_user)

        group = GroupService.by_group_name(ADMIN_GROUP, db_session=db)
        admin = UserService.by_user_name(ADMIN_USER, db_session=db)

        group_entry = models.UserGroup(group_id=group.id, user_id=admin.id)
        db.add(group_entry)

        new_group_permission = models.GroupPermission(perm_name=ADMIN_PERM, group_id=group.id)
        db.add(new_group_permission)
        
    else:
        LOGGER.debug('admin already initialized')


def init_user(db_session):
    db = db_session
    if not GroupService.by_group_name(USER_GROUP, db_session=db):
        admin_group = models.Group(group_name=USER_GROUP)
        db.add(admin_group)
        
    else:
        LOGGER.debug('group USER already initialized')


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

def main(global_config, **settings):
    """
    This function returns a Pyramid WSGI application.
    """
    hostname = os.getenv('HOSTNAME')
    if hostname:
        settings['magpie.url'] = 'http://{hostname}:{port}'.format(hostname=hostname, port=settings['magpie.port'])


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

    # Initialize database with default user: admin+anonymous
    import transaction
    from db import get_tm_session
    session_factory = config.registry['dbsession_factory']
    db = get_tm_session(session_factory, transaction)
    try:
        current_rev = get_database_revision(db_session=db)
        LOGGER.info('current_rev : ' + str(current_rev))
    except:
        init_db() # Get out the initialization in an other script that I will run with supervisor because the multiple workers overlape

    init_admin(db_session=db)
    init_user(db_session=db)
    init_anonymous(db_session=db)
    db.close()

    return config.make_wsgi_app()


if __name__ == '__main__':
    main()

