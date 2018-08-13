#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import shutil
import dotenv
import logging
from magpie.common import str2bool, raise_log, print_log

# ===========================
# path variables
# ===========================
MAGPIE_MODULE_DIR = os.path.abspath(os.path.dirname(__file__))
MAGPIE_ROOT = os.path.dirname(MAGPIE_MODULE_DIR)
MAGPIE_PROVIDERS_CONFIG_PATH = '{}/providers.cfg'.format(MAGPIE_ROOT)
MAGPIE_INI_FILE_PATH = '{}/magpie.ini'.format(MAGPIE_MODULE_DIR)
MAGPIE_ALEMBIC_INI_FILE_PATH = '{}/alembic/alembic.ini'.format(MAGPIE_MODULE_DIR)
MAGPIE_ENV_FILE = os.path.join(MAGPIE_MODULE_DIR, 'env', 'magpie.env')
MAGPIE_POSTGRES_ENV_FILE = os.path.join(MAGPIE_MODULE_DIR, 'env', 'postgres.env')

# create .env from .env.example if not present and load variables into environment
if not os.path.isfile(MAGPIE_ENV_FILE):
    shutil.copyfile(MAGPIE_ENV_FILE + ".example", MAGPIE_ENV_FILE)
if not os.path.isfile(MAGPIE_POSTGRES_ENV_FILE):
    shutil.copyfile(MAGPIE_POSTGRES_ENV_FILE + ".example", MAGPIE_POSTGRES_ENV_FILE)
dotenv.load_dotenv(MAGPIE_ENV_FILE, override=False)
dotenv.load_dotenv(MAGPIE_POSTGRES_ENV_FILE, override=False)

# ===========================
# variables from magpie.env
# ===========================
MAGPIE_SECRET = os.getenv('MAGPIE_SECRET', 'seekrit')
MAGPIE_ADMIN_USER = os.getenv('MAGPIE_ADMIN_USER', 'admin')
MAGPIE_ADMIN_PASSWORD = os.getenv('MAGPIE_ADMIN_PASSWORD', 'qwerty')
MAGPIE_ADMIN_EMAIL = '{}@mail.com'.format(MAGPIE_ADMIN_USER)
MAGPIE_ADMIN_GROUP = os.getenv('MAGPIE_ADMIN_GROUP', 'administrators')
MAGPIE_ANONYMOUS_USER = os.getenv('MAGPIE_ANONYMOUS_USER', 'anonymous')
MAGPIE_ANONYMOUS_PASSWORD = MAGPIE_ANONYMOUS_USER
MAGPIE_ANONYMOUS_EMAIL = '{}@mail.com'.format(MAGPIE_ANONYMOUS_USER)
MAGPIE_ANONYMOUS_GROUP = MAGPIE_ANONYMOUS_USER
MAGPIE_USERS_GROUP = os.getenv('MAGPIE_USERS_GROUP', 'users')
PHOENIX_USER = os.getenv('PHOENIX_USER', 'phoenix')
PHOENIX_PASSWORD = os.getenv('PHOENIX_PASSWORD', 'qwerty')
PHOENIX_PORT = int(os.getenv('PHOENIX_PORT', 8443))
PHOENIX_PUSH = str2bool(os.getenv('PHOENIX_PUSH', True))
TWITCHER_PROTECTED_PATH = os.getenv('TWITCHER_PROTECTED_PATH', '/ows/proxy')

# ===========================
# variables from postgres.env
# ===========================
MAGPIE_POSTGRES_USER = os.getenv('MAGPIE_POSTGRES_USER', 'magpie')
MAGPIE_POSTGRES_PASSWORD = os.getenv('MAGPIE_POSTGRES_PASSWORD', 'qwerty')
MAGPIE_POSTGRES_HOST = os.getenv('MAGPIE_POSTGRES_HOST', 'postgres')
MAGPIE_POSTGRES_PORT = int(os.getenv('MAGPIE_POSTGRES_PORT', 5432))
MAGPIE_POSTGRES_DB = os.getenv('MAGPIE_POSTGRES_DB', 'magpiedb')

# ===========================
# other constants
# ===========================
MAGPIE_ADMIN_PERMISSION = 'admin'
#MAGPIE_ADMIN_PERMISSION = NO_PERMISSION_REQUIRED

MAGPIE_LOGGED_USER = 'current'

# above this length is considered a token,
# refuse longer username creation
MAGPIE_USER_NAME_MAX_LENGTH = 64

# ===========================
# utilities
# ===========================


def get_constant(name, settings=None, settings_name=None,
                 raise_missing=True, print_missing=False, raise_not_set=True):
    """
    Search in order for matched value of `name` :
      1. search in magpie definitions
      2. search in environment variables
      3. search in settings if specified

    :param name: key to search for a value
    :param settings: wsgi app settings
    :param settings_name: alternative name for `settings` if specified
    :param raise_missing: raise exception if key is not found anywhere
    :param print_missing: print message if key is not found anywhere, return None
    :param raise_not_set: raise an exception if the found key is None, search until last case if previous are None
    :returns: found value or None
    :raises: according message based on options (by default raise missing/None value)
    """
    magpie_globals = globals()
    missing = True
    magpie_value = None
    if name in magpie_globals:
        missing = False
        magpie_value = magpie_globals.get(name)
        if magpie_value is not None:
            return magpie_value
    if name in os.environ:
        missing = False
        magpie_value = os.environ.get(name)
        if magpie_value is not None:
            return magpie_value
    if settings and name in settings:
        missing = False
        magpie_value = settings.get(name)
        if magpie_value is not None:
            return magpie_value
    if settings and settings_name and settings_name in settings:
        missing = False
        magpie_value = settings.get(settings_name)
        if magpie_value is not None:
            return magpie_value
    if not missing and raise_not_set:
        raise_log("Constant was found but was not set: {}".format(name), level=logging.ERROR)
    if missing and raise_missing:
        raise_log("Constant could not be found: {}".format(name), level=logging.ERROR)
    if missing and print_missing:
        print_log("Constant could not be found: {}".format(name), level=logging.WARN)
    return magpie_value
