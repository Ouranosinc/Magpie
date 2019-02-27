#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import shutil
# noinspection PyPackageRequirements
import dotenv
import logging
import warnings
from magpie.common import str2bool, raise_log, print_log, get_settings_from_config_ini

# ===========================
# path variables
# ===========================
MAGPIE_MODULE_DIR = os.path.abspath(os.path.dirname(__file__))
MAGPIE_ROOT = os.path.dirname(MAGPIE_MODULE_DIR)
MAGPIE_CONFIG_DIR = os.getenv(
    'MAGPIE_CONFIG_DIR', os.path.join(MAGPIE_ROOT, 'config'))
MAGPIE_PROVIDERS_CONFIG_PATH = os.getenv(
    'MAGPIE_PROVIDERS_CONFIG_PATH', '{}/providers.cfg'.format(MAGPIE_CONFIG_DIR))
MAGPIE_PERMISSIONS_CONFIG_PATH = os.getenv(
    'MAGPIE_PERMISSIONS_CONFIG_PATH', '{}/permissions.cfg'.format(MAGPIE_CONFIG_DIR))
MAGPIE_INI_FILE_PATH = os.getenv(
    'MAGPIE_INI_FILE_PATH', '{}/magpie.ini'.format(MAGPIE_MODULE_DIR))
MAGPIE_ALEMBIC_INI_FILE_PATH = os.getenv(
    'MAGPIE_ALEMBIC_INI_FILE_PATH', '{}/alembic/alembic.ini'.format(MAGPIE_MODULE_DIR))
# allow custom location of env files directory to avoid
# loading from installed magpie in python site-packages
MAGPIE_ENV_DIR = os.getenv('MAGPIE_ENV_DIR', os.path.join(MAGPIE_ROOT, 'env'))
MAGPIE_ENV_FILE = os.path.join(MAGPIE_ENV_DIR, 'magpie.env')
MAGPIE_POSTGRES_ENV_FILE = os.path.join(MAGPIE_ENV_DIR, 'postgres.env')

# create .env from .env.example if not present and load variables into environment
# if files still cannot be found at 'MAGPIE_ENV_DIR' and variables are still not set,
# default values in following sections will be used instead
magpie_env_example = MAGPIE_ENV_FILE + ".example"
postgres_env_example = MAGPIE_ENV_FILE + ".example"
if not os.path.isfile(MAGPIE_ENV_FILE) and os.path.isfile(magpie_env_example):
    shutil.copyfile(magpie_env_example, MAGPIE_ENV_FILE)
if not os.path.isfile(MAGPIE_POSTGRES_ENV_FILE) and os.path.isfile(postgres_env_example):
    shutil.copyfile(postgres_env_example, MAGPIE_POSTGRES_ENV_FILE)
del magpie_env_example
del postgres_env_example
try:
    # if variables already exist, don't override them from defaults in env files
    dotenv.load_dotenv(MAGPIE_ENV_FILE, override=False)
    dotenv.load_dotenv(MAGPIE_POSTGRES_ENV_FILE, override=False)
except IOError:
    warnings.warn("Failed to open environment files [MAGPIE_ENV_DIR={}].".format(MAGPIE_ENV_DIR), RuntimeWarning)
    pass

# get default configurations from ini file
_default_log_lvl = 'INFO'
# noinspection PyBroadException
try:
    _settings = get_settings_from_config_ini(MAGPIE_INI_FILE_PATH, ini_main_section_name='logger_magpie')
    _default_log_lvl = _settings.get('level', _default_log_lvl)
except Exception:
    pass

# ===========================
# variables from magpie.env
# ===========================
MAGPIE_SECRET = os.getenv('MAGPIE_SECRET', 'seekrit')
MAGPIE_COOKIE_NAME = os.getenv('MAGPIE_COOKIE_NAME', 'auth_tkt')
MAGPIE_COOKIE_EXPIRE = os.getenv('MAGPIE_COOKIE_EXPIRE', None)
MAGPIE_ADMIN_USER = os.getenv('MAGPIE_ADMIN_USER', 'admin')
MAGPIE_ADMIN_PASSWORD = os.getenv('MAGPIE_ADMIN_PASSWORD', 'qwerty')
MAGPIE_ADMIN_EMAIL = '{}@mail.com'.format(MAGPIE_ADMIN_USER)
MAGPIE_ADMIN_GROUP = os.getenv('MAGPIE_ADMIN_GROUP', 'administrators')
MAGPIE_ANONYMOUS_USER = os.getenv('MAGPIE_ANONYMOUS_USER', 'anonymous')
MAGPIE_ANONYMOUS_PASSWORD = MAGPIE_ANONYMOUS_USER
MAGPIE_ANONYMOUS_EMAIL = '{}@mail.com'.format(MAGPIE_ANONYMOUS_USER)
MAGPIE_ANONYMOUS_GROUP = MAGPIE_ANONYMOUS_USER
MAGPIE_EDITOR_GROUP = os.getenv('MAGPIE_EDITOR_GROUP', 'editors')
MAGPIE_USERS_GROUP = os.getenv('MAGPIE_USERS_GROUP', 'users')
MAGPIE_CRON_LOG = os.getenv('MAGPIE_CRON_LOG', '~/magpie-cron.log')
MAGPIE_LOG_LEVEL = os.getenv('MAGPIE_LOG_LEVEL', _default_log_lvl)
PHOENIX_USER = os.getenv('PHOENIX_USER', 'phoenix')
PHOENIX_PASSWORD = os.getenv('PHOENIX_PASSWORD', 'qwerty')
PHOENIX_PORT = int(os.getenv('PHOENIX_PORT', 8443))
PHOENIX_PUSH = str2bool(os.getenv('PHOENIX_PUSH', True))
TWITCHER_PROTECTED_PATH = os.getenv('TWITCHER_PROTECTED_PATH', '/ows/proxy')
TWITCHER_PROTECTED_URL = os.getenv('TWITCHER_PROTECTED_URL', None)

# ===========================
# variables from postgres.env
# ===========================
MAGPIE_POSTGRES_USER = os.getenv('MAGPIE_POSTGRES_USER', 'magpie')
MAGPIE_POSTGRES_PASSWORD = os.getenv('MAGPIE_POSTGRES_PASSWORD', 'qwerty')
MAGPIE_POSTGRES_HOST = os.getenv('MAGPIE_POSTGRES_HOST', 'postgres')
MAGPIE_POSTGRES_PORT = int(os.getenv('MAGPIE_POSTGRES_PORT', 5432))
MAGPIE_POSTGRES_DB = os.getenv('MAGPIE_POSTGRES_DB', 'magpie')

# ===========================
# other constants
# ===========================
MAGPIE_ADMIN_PERMISSION = 'admin'
# MAGPIE_ADMIN_PERMISSION = NO_PERMISSION_REQUIRED
MAGPIE_LOGGED_USER = 'current'
MAGPIE_DEFAULT_PROVIDER = 'ziggurat'

# above this length is considered a token,
# refuse longer username creation
MAGPIE_USER_NAME_MAX_LENGTH = 64

# ===========================
# utilities
# ===========================


def get_constant(name, settings=None, settings_name=None, default_value=None,
                 raise_missing=True, print_missing=False, raise_not_set=True):
    """
    Search in order for matched value of `name` :
      1. search in magpie definitions
      2. search in environment variables
      3. search in settings if specified

    :param name: key to search for a value
    :param settings: wsgi app settings
    :param settings_name: alternative name for `settings` if specified
    :param default_value: default value to be returned if not found anywhere, and exception raises are disabled.
    :param raise_missing: raise exception if key is not found anywhere
    :param print_missing: print message if key is not found anywhere, return None
    :param raise_not_set: raise an exception if the found key is None, search until last case if previous are None
    :returns: found value or :param:`default_value`
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
        print_log("Constant could not be found: {} (using default: {})".format(name, default_value), level=logging.WARN)
    return magpie_value or default_value
