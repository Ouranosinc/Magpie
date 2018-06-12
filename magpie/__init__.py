# -*- coding: utf-8 -*-

import os
import sys
this_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, this_dir)

ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_GROUP = os.getenv('ADMIN_GROUP', 'administrators')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')

USER_GROUP = os.getenv('USER_GROUP', 'users')

ANONYMOUS_USER = os.getenv('ANONYMOUS_USER', 'anonymous')

ADMIN_PERM = 'admin'
#ADMIN_PERM = NO_PERMISSION_REQUIRED

LOGGED_USER = 'current'

# above this length is considered a token,
# refuse longer username creation
USER_NAME_MAX_LENGTH = 64


def includeme(config):
    config.include('magpie.api')
    config.include('magpie.home')
    config.include('magpie.login')
    config.include('magpie.management')
    config.include('magpie.ui')
