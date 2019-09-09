#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Constant settings for Magpie application.

Constants defined with format ``MAGPIE_[VARIABLE_NAME]`` can be matched with corresponding
settings formatted as ``magpie.[variable_name]`` in the ``magpie.ini`` configuration file.

.. note::
    Since the ``magpie.ini`` file has to be loaded by the application to retrieve various configuration settings,
    constant ``MAGPIE_INI_FILE_PATH`` (or any other `path variable` defined before it - see below) has to be defined
    by environment variable if the default location is not desired (ie: if you want to provide your own configuration).
"""
from magpie.definitions.pyramid_definitions import asbool
from typing import TYPE_CHECKING
import re
import os
import shutil
import dotenv
import logging
import warnings
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Str, Optional, SettingValue, AnySettingsContainer  # noqa: F401

# ===========================
# path variables
# ===========================
MAGPIE_MODULE_DIR = os.path.abspath(os.path.dirname(__file__))
MAGPIE_ROOT = os.path.dirname(MAGPIE_MODULE_DIR)
MAGPIE_CONFIG_DIR = os.getenv(
    "MAGPIE_CONFIG_DIR", os.path.join(MAGPIE_ROOT, "config"))
MAGPIE_PROVIDERS_CONFIG_PATH = os.getenv(
    "MAGPIE_PROVIDERS_CONFIG_PATH", "{}/providers.cfg".format(MAGPIE_CONFIG_DIR))
MAGPIE_PERMISSIONS_CONFIG_PATH = os.getenv(
    "MAGPIE_PERMISSIONS_CONFIG_PATH", "{}/permissions.cfg".format(MAGPIE_CONFIG_DIR))
MAGPIE_INI_FILE_PATH = os.getenv(
    "MAGPIE_INI_FILE_PATH", "{}/magpie.ini".format(MAGPIE_CONFIG_DIR))
MAGPIE_ALEMBIC_INI_FILE_PATH = os.getenv(
    "MAGPIE_ALEMBIC_INI_FILE_PATH", MAGPIE_INI_FILE_PATH)
# allow custom location of env files directory to avoid
# loading from installed magpie in python site-packages
MAGPIE_ENV_DIR = os.getenv("MAGPIE_ENV_DIR", os.path.join(MAGPIE_ROOT, "env"))
MAGPIE_ENV_FILE = os.path.join(MAGPIE_ENV_DIR, "magpie.env")
MAGPIE_POSTGRES_ENV_FILE = os.path.join(MAGPIE_ENV_DIR, "postgres.env")

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


def _get_default_log_level():
    """Get default configurations from ini file."""
    _default_log_lvl = "INFO"
    # noinspection PyBroadException
    try:
        import magpie.utils
        _settings = magpie.utils.get_settings_from_config_ini(MAGPIE_INI_FILE_PATH,
                                                              ini_main_section_name="logger_magpie")
        _default_log_lvl = _settings.get("level", _default_log_lvl)
    except Exception:
        pass
    return _default_log_lvl


# ===========================
# variables from magpie.env
# ===========================
MAGPIE_URL = os.getenv("MAGPIE_URL", None)
MAGPIE_SECRET = os.getenv("MAGPIE_SECRET", "seekrit")
MAGPIE_COOKIE_NAME = os.getenv("MAGPIE_COOKIE_NAME", "auth_tkt")
MAGPIE_COOKIE_EXPIRE = os.getenv("MAGPIE_COOKIE_EXPIRE", None)
MAGPIE_ADMIN_USER = os.getenv("MAGPIE_ADMIN_USER", "admin")
MAGPIE_ADMIN_PASSWORD = os.getenv("MAGPIE_ADMIN_PASSWORD", "qwerty")
MAGPIE_ADMIN_EMAIL = "{}@mail.com".format(MAGPIE_ADMIN_USER)
MAGPIE_ADMIN_GROUP = os.getenv("MAGPIE_ADMIN_GROUP", "administrators")
MAGPIE_ANONYMOUS_USER = os.getenv("MAGPIE_ANONYMOUS_USER", "anonymous")
MAGPIE_ANONYMOUS_PASSWORD = MAGPIE_ANONYMOUS_USER
MAGPIE_ANONYMOUS_EMAIL = "{}@mail.com".format(MAGPIE_ANONYMOUS_USER)
MAGPIE_ANONYMOUS_GROUP = MAGPIE_ANONYMOUS_USER  # left for backward compatibility of migration scripts
MAGPIE_EDITOR_GROUP = os.getenv("MAGPIE_EDITOR_GROUP", "editors")
MAGPIE_USERS_GROUP = os.getenv("MAGPIE_USERS_GROUP", "users")
MAGPIE_CRON_LOG = os.getenv("MAGPIE_CRON_LOG", "~/magpie-cron.log")
MAGPIE_DB_MIGRATION = asbool(os.getenv("MAGPIE_DB_MIGRATION", True))            # run db migration on startup
MAGPIE_DB_MIGRATION_ATTEMPTS = int(os.getenv("MAGPIE_DB_MIGRATION_ATTEMPTS", 5))
MAGPIE_LOG_LEVEL = os.getenv("MAGPIE_LOG_LEVEL", _get_default_log_level())      # log level to apply to the loggers
MAGPIE_LOG_PRINT = asbool(os.getenv("MAGPIE_LOG_PRINT", False))                 # log also forces print to the console
MAGPIE_LOG_REQUEST = asbool(os.getenv("MAGPIE_LOG_REQUEST", True))              # log detail of every incoming request
MAGPIE_LOG_EXCEPTION = asbool(os.getenv("MAGPIE_LOG_EXCEPTION", True))          # log detail of generated exceptions
MAGPIE_UI_ENABLED = asbool(os.getenv("MAGPIE_UI_ENABLED", True))
PHOENIX_USER = os.getenv("PHOENIX_USER", "phoenix")
PHOENIX_PASSWORD = os.getenv("PHOENIX_PASSWORD", "qwerty")
PHOENIX_PORT = int(os.getenv("PHOENIX_PORT", 8443))
PHOENIX_PUSH = asbool(os.getenv("PHOENIX_PUSH", True))
TWITCHER_PROTECTED_PATH = os.getenv("TWITCHER_PROTECTED_PATH", "/ows/proxy")
TWITCHER_PROTECTED_URL = os.getenv("TWITCHER_PROTECTED_URL", None)

# ===========================
# variables from postgres.env
# ===========================
MAGPIE_POSTGRES_USER = os.getenv("MAGPIE_POSTGRES_USER", "magpie")
MAGPIE_POSTGRES_PASSWORD = os.getenv("MAGPIE_POSTGRES_PASSWORD", "qwerty")
MAGPIE_POSTGRES_HOST = os.getenv("MAGPIE_POSTGRES_HOST", "postgres")
MAGPIE_POSTGRES_PORT = int(os.getenv("MAGPIE_POSTGRES_PORT", 5432))
MAGPIE_POSTGRES_DB = os.getenv("MAGPIE_POSTGRES_DB", "magpie")

# ===========================
# other constants
# ===========================
MAGPIE_ADMIN_PERMISSION = "admin"
# MAGPIE_ADMIN_PERMISSION = NO_PERMISSION_REQUIRED
MAGPIE_LOGGED_USER = "current"
MAGPIE_DEFAULT_PROVIDER = "ziggurat"

# above this length is considered a token,
# refuse longer username creation
MAGPIE_USER_NAME_MAX_LENGTH = 64

# ===========================
# utilities
# ===========================

_REGEX_ASCII_ONLY = re.compile(r'\W|^(?=\d)')

def get_constant_setting_name(name):
    """Lower-case name and replace all non-ascii chars by `_`."""
    name = re.sub(_REGEX_ASCII_ONLY, '_', name.strip().lower())
    return name.replace('magpie_', 'magpie.', 1)


def get_constant(constant_name,             # type: Str
                 settings_container=None,   # type: Optional[AnySettingsContainer]
                 settings_name=None,        # type: Optional[Str]
                 default_value=None,        # type: Optional[SettingValue]
                 raise_missing=True,        # type: bool
                 print_missing=False,       # type: bool
                 raise_not_set=True         # type: bool
                 ):                         # type: (...) -> SettingValue
    """
    Search in order for matched value of ``constant_name``:
      1. search in settings if specified
      2. search alternative setting names
      3. search in ``magpie.constants`` definitions
      4. search in environment variables

    Parameter ``constant_name`` is expected to have the format ``MAGPIE_[VARIABLE_NAME]`` although any value can
    be passed to retrieve generic settings from all above mentioned search locations.

    If ``settings_name`` is provided as alternative name, it is used as is to search for results if ``constant_name``
    was not found. Otherwise, ``magpie.[variable_name]`` is used for additional search when the format
    ``MAGPIE_[VARIABLE_NAME]`` was used for ``constant_name``
    (ie: ``MAGPIE_ADMIN_USER`` will also search for ``magpie.admin_user`` and so on for corresponding constants).

    :param constant_name: key to search for a value
    :param settings_container: wsgi app settings container
    :param settings_name: alternative name for `settings` if specified
    :param default_value: default value to be returned if not found anywhere, and exception raises are disabled.
    :param raise_missing: raise exception if key is not found anywhere
    :param print_missing: print message if key is not found anywhere, return `None`
    :param raise_not_set: raise an exception if the found key is None, search until last case if previous are `None`
    :returns: found value or `default_value`
    :raises: according message based on options (by default raise missing/`None` value)
    """
    from magpie.utils import get_settings, raise_log, print_log

    missing = True
    magpie_value = None
    settings = get_settings(settings_container) if settings_container else None
    if settings and constant_name in settings:
        missing = False
        magpie_value = settings.get(constant_name)
        if magpie_value is not None:
            print_log("Constant found in settings with: {}".format(constant_name), level=logging.DEBUG)
            return magpie_value
    if not settings_name and constant_name.startswith("MAGPIE_"):
        settings_name = get_constant_setting_name(constant_name)
        print_log("Constant alternate search: {}".format(settings_name), level=logging.DEBUG)
    if settings and settings_name and settings_name in settings:
        missing = False
        magpie_value = settings.get(settings_name)
        if magpie_value is not None:
            print_log("Constant found in settings with: {}".format(settings_name), level=logging.DEBUG)
            return magpie_value
    magpie_globals = globals()
    if constant_name in magpie_globals:
        missing = False
        magpie_value = magpie_globals.get(constant_name)
        if magpie_value is not None:
            print_log("Constant found in definitions with: {}".format(constant_name), level=logging.DEBUG)
            return magpie_value
    if constant_name in os.environ:
        missing = False
        magpie_value = os.environ.get(constant_name)
        if magpie_value is not None:
            print_log("Constant found in environment with: {}".format(constant_name), level=logging.DEBUG)
            return magpie_value
    if not missing and raise_not_set:
        raise_log("Constant was found but was not set: {}".format(constant_name),
                  level=logging.ERROR, exception=ValueError)
    if missing and raise_missing:
        raise_log("Constant could not be found: {}".format(constant_name),
                  level=logging.ERROR, exception=LookupError)
    if missing and print_missing:
        print_log("Constant could not be found: {} (using default: {})"
                  .format(constant_name, default_value), level=logging.WARN)
    return magpie_value or default_value
