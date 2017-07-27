#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations
"""

# -- Standard library --------------------------------------------------------
import logging.config
import argparse
import os

# -- Ziggurat_foundation ----
from ziggurat_foundations.models import groupfinder


# -- Pyramid ----
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import SignedCookieSessionFactory

# -- Project specific --------------------------------------------------------
#from .__meta__ import __version__ as __ver__
#import models
from __init__ import *

THIS_DIR = os.path.dirname(__file__)

def main(global_config, **settings):
    """
    This function returns a Pyramid WSGI application.
    """
    from pyramid.config import Configurator
    config = Configurator(settings=settings)
    session_factory = SignedCookieSessionFactory(settings['auth.secret'])

    authn_policy = AuthTktAuthenticationPolicy(
        settings['auth.secret'],
        callback=groupfinder,
    )
    authz_policy = ACLAuthorizationPolicy()

    '''
    config = Configurator(
        settings=settings,
        authentication_policy=authn_policy,
        authorization_policy=authz_policy,
        root_factory=models.RootFactory,
        session_factory=session_factory,
    )
    '''
    config = Configurator(
        settings=settings,
        authentication_policy=authn_policy,
        authorization_policy=authz_policy
    )


    # include magpie components (all the file which define includeme)
    config.include('pyramid_chameleon')
    config.include('login')
    config.include('home')
    config.include('db')
    config.include('management')

    config.scan('magpie')

    return config.make_wsgi_app()


if __name__ == '__main__':
    main()

