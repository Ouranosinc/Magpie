#!/usr/bin/python
# -*- coding: utf-8 -*-
import os

MAGPIE_MODULE_DIR = os.path.abspath(os.path.dirname(__file__))
MAGPIE_ROOT = os.path.dirname(MAGPIE_MODULE_DIR)

MAGPIE_PROVIDERS_CONFIG_PATH = '{}/providers.cfg'.format(MAGPIE_ROOT)
MAGPIE_INI_FILE_PATH = '{}/magpie.ini'.format(MAGPIE_MODULE_DIR)

ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_GROUP = os.getenv('ADMIN_GROUP', 'administrators')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')
ADMIN_EMAIL = '{}@mail.com'.format(ADMIN_USER)

USERS_GROUP = os.getenv('USERS_GROUP', 'users')

ANONYMOUS_USER = os.getenv('ANONYMOUS_USER', 'anonymous')
ANONYMOUS_GROUP = ANONYMOUS_USER
ANONYMOUS_PASSWORD = ANONYMOUS_USER
ANONYMOUS_EMAIL = '{}@mail.com'.format(ANONYMOUS_USER)

ADMIN_PERMISSION = 'admin'
#ADMIN_PERMISSION = NO_PERMISSION_REQUIRED

LOGGED_USER = 'current'

# above this length is considered a token,
# refuse longer username creation
USER_NAME_MAX_LENGTH = 64
