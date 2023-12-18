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
import logging
import os
import re
import shutil
import sys
import warnings
from typing import TYPE_CHECKING

import dotenv
from pyramid.settings import asbool

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import List, Optional

    from magpie.typedefs import AnySettingsContainer, SettingValue, Str

# ===========================
# path variables
# ===========================
MAGPIE_MODULE_DIR = os.path.abspath(os.path.dirname(__file__))
MAGPIE_ROOT = os.path.dirname(MAGPIE_MODULE_DIR)
MAGPIE_CONFIG_DIR = os.getenv("MAGPIE_CONFIG_DIR") or os.path.join(MAGPIE_ROOT, "config")  # default also if empty
MAGPIE_PROVIDERS_CONFIG_PATH = os.getenv(
    "MAGPIE_PROVIDERS_CONFIG_PATH", "{}/providers.cfg".format(MAGPIE_CONFIG_DIR))
MAGPIE_PROVIDERS_HOOKS_PATH = os.getenv("MAGPIE_PROVIDERS_HOOKS_PATH", MAGPIE_ROOT)
MAGPIE_PERMISSIONS_CONFIG_PATH = os.getenv(
    "MAGPIE_PERMISSIONS_CONFIG_PATH", "{}/permissions.cfg".format(MAGPIE_CONFIG_DIR))
MAGPIE_WEBHOOKS_CONFIG_PATH = os.getenv("MAGPIE_WEBHOOKS_CONFIG_PATH")
MAGPIE_CONFIG_PATH = os.getenv("MAGPIE_CONFIG_PATH")  # default None, require explicit specification
MAGPIE_INI_FILE_PATH = os.getenv(
    "MAGPIE_INI_FILE_PATH", "{}/magpie.ini".format(MAGPIE_CONFIG_DIR))
# allow custom location of env files directory to avoid
# loading from installed magpie in python site-packages
MAGPIE_ENV_DIR = os.getenv("MAGPIE_ENV_DIR", os.path.join(MAGPIE_ROOT, "env"))
MAGPIE_ENV_FILE = os.path.join(MAGPIE_ENV_DIR, "magpie.env")
MAGPIE_POSTGRES_ENV_FILE = os.path.join(MAGPIE_ENV_DIR, "postgres.env")

# create .env from .env.example if not present and load variables into environment
# if files still cannot be found at 'MAGPIE_ENV_DIR' and variables are still not set,
# default values in following sections will be used instead
_MAGPIE_ENV_EXAMPLE = MAGPIE_ENV_FILE + ".example"
_POSTGRES_ENV_EXAMPLE = MAGPIE_POSTGRES_ENV_FILE + ".example"
if not os.path.isfile(MAGPIE_ENV_FILE) and os.path.isfile(_MAGPIE_ENV_EXAMPLE):
    shutil.copyfile(_MAGPIE_ENV_EXAMPLE, MAGPIE_ENV_FILE)
if not os.path.isfile(MAGPIE_POSTGRES_ENV_FILE) and os.path.isfile(_POSTGRES_ENV_EXAMPLE):
    shutil.copyfile(_POSTGRES_ENV_EXAMPLE, MAGPIE_POSTGRES_ENV_FILE)
del _MAGPIE_ENV_EXAMPLE
del _POSTGRES_ENV_EXAMPLE
try:
    # if variables already exist, don't override them from defaults in env files
    dotenv.load_dotenv(MAGPIE_ENV_FILE, override=False)
    dotenv.load_dotenv(MAGPIE_POSTGRES_ENV_FILE, override=False)
except IOError:
    warnings.warn("Failed to open environment files [MAGPIE_ENV_DIR={}].".format(MAGPIE_ENV_DIR), RuntimeWarning)


def _get_default_log_level():
    # type: () -> Str
    """
    Get logging level from INI configuration file or fallback to default ``INFO`` if it cannot be retrieved.
    """
    _default_log_lvl = "INFO"
    try:
        import magpie.utils  # pylint: disable=C0415  # avoid circular import error
        _settings = magpie.utils.get_settings_from_config_ini(MAGPIE_INI_FILE_PATH,
                                                              ini_main_section_name="logger_magpie")
        _default_log_lvl = _settings.get("level", _default_log_lvl)
    # also considers 'ModuleNotFoundError' derived from 'ImportError', but not added to avoid Python <3.6 name error
    except (AttributeError, ImportError):  # noqa: W0703 # nosec: B110
        pass
    return _default_log_lvl


# ===========================
# variables from magpie.env
# ===========================
MAGPIE_URL = os.getenv("MAGPIE_URL", None)
MAGPIE_SECRET = os.getenv("MAGPIE_SECRET", "")
MAGPIE_COOKIE_NAME = os.getenv("MAGPIE_COOKIE_NAME", "auth_tkt")
MAGPIE_COOKIE_EXPIRE = os.getenv("MAGPIE_COOKIE_EXPIRE", None)
MAGPIE_PASSWORD_MIN_LENGTH = os.getenv("MAGPIE_PASSWORD_MIN_LENGTH", 12)
MAGPIE_ADMIN_USER = os.getenv("MAGPIE_ADMIN_USER", "")
MAGPIE_ADMIN_PASSWORD = os.getenv("MAGPIE_ADMIN_PASSWORD", "")
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
MAGPIE_NETWORK_ENABLED = asbool(os.getenv("MAGPIE_NETWORK_ENABLED", False))
MAGPIE_NETWORK_INSTANCE_NAME = os.getenv("MAGPIE_NETWORK_INSTANCE_NAME")
MAGPIE_NETWORK_DEFAULT_TOKEN_EXPIRY = int(os.getenv("MAGPIE_NETWORK_DEFAULT_TOKEN_EXPIRY", 86400))
MAGPIE_NETWORK_INTERNAL_TOKEN_EXPIRY = int(os.getenv("MAGPIE_NETWORK_INTERNAL_TOKEN_EXPIRY", 30))
MAGPIE_NETWORK_PEM_FILES = os.getenv("MAGPIE_NETWORK_PEM_FILES", os.path.join(MAGPIE_ROOT, "key.pem"))
MAGPIE_NETWORK_PEM_PASSWORDS = os.getenv("MAGPIE_NETWORK_PEM_PASSWORDS")
MAGPIE_LOG_LEVEL = os.getenv("MAGPIE_LOG_LEVEL", _get_default_log_level())      # log level to apply to the loggers
MAGPIE_LOG_PRINT = asbool(os.getenv("MAGPIE_LOG_PRINT", False))                 # log also forces print to the console
MAGPIE_LOG_REQUEST = asbool(os.getenv("MAGPIE_LOG_REQUEST", True))              # log detail of every incoming request
MAGPIE_LOG_EXCEPTION = asbool(os.getenv("MAGPIE_LOG_EXCEPTION", True))          # log detail of generated exceptions
MAGPIE_UI_ENABLED = asbool(os.getenv("MAGPIE_UI_ENABLED", True))
MAGPIE_UI_THEME = os.getenv("MAGPIE_UI_THEME", "blue")
PHOENIX_USER = os.getenv("PHOENIX_USER", "phoenix")
PHOENIX_PASSWORD = os.getenv("PHOENIX_PASSWORD", "qwerty")
PHOENIX_HOST = os.getenv("PHOENIX_HOST")  # default None to use HOSTNAME
PHOENIX_PORT = int(os.getenv("PHOENIX_PORT", 8443))
PHOENIX_PUSH = asbool(os.getenv("PHOENIX_PUSH", False))
TWITCHER_PROTECTED_PATH = os.getenv("TWITCHER_PROTECTED_PATH", "/ows/proxy")
TWITCHER_PROTECTED_URL = os.getenv("TWITCHER_PROTECTED_URL", None)
TWITCHER_HOST = os.getenv("TWITCHER_HOST", None)

# external identify connectors, define variables only to avoid unnecessary print-log warnings in each CLI call
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", None)
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", None)
WSO2_HOSTNAME = os.getenv("WSO2_HOSTNAME", None)
WSO2_CLIENT_ID = os.getenv("WSO2_CLIENT_ID", None)
WSO2_CLIENT_SECRET = os.getenv("WSO2_CLIENT_SECRET", None)
WSO2_CERTIFICATE_FILE = os.getenv("WSO2_CERTIFICATE_FILE", None)
WSO2_SSL_VERIFY = os.getenv("WSO2_SSL_VERIFY", None)

# ===========================
# variables from postgres.env
# ===========================
MAGPIE_POSTGRES_USERNAME = os.getenv("MAGPIE_POSTGRES_USERNAME", "magpie")
MAGPIE_POSTGRES_PASSWORD = os.getenv("MAGPIE_POSTGRES_PASSWORD", "qwerty")
MAGPIE_POSTGRES_HOST = os.getenv("MAGPIE_POSTGRES_HOST", "postgres")
MAGPIE_POSTGRES_PORT = int(os.getenv("MAGPIE_POSTGRES_PORT", 5432))
MAGPIE_POSTGRES_DB = os.getenv("MAGPIE_POSTGRES_DB", "magpie")

# ===========================
# constants
# ===========================
MAGPIE_ADMIN_PERMISSION = "admin"   # user must be administrator to access a view (default permission, always allowed)
MAGPIE_LOGGED_PERMISSION = "MAGPIE_LOGGED_USER"  # user must be itself (either literally or inferred MAGPIE_LOGGED_USER)
MAGPIE_CONTEXT_PERMISSION = "MAGPIE_CONTEXT_USER"  # path user must be itself, MAGPIE_LOGGED_USER or unauthenticated
MAGPIE_LOGGED_USER = "current"
MAGPIE_DEFAULT_PROVIDER = "ziggurat"
MAGPIE_NETWORK_TOKEN_NAME = "magpie_token"  # nosec: B105
MAGPIE_NETWORK_PROVIDER = "magpie_network"
MAGPIE_NETWORK_NAME_PREFIX = "anonymous_network_"
MAGPIE_NETWORK_ANONYMOUS_EMAIL_FORMAT = "{}{}@mail.com".format(MAGPIE_NETWORK_NAME_PREFIX, "{}")
MAGPIE_NETWORK_GROUP_NAME = "magpie_network"

# above this length is considered a token,
# refuse longer username creation
MAGPIE_USER_NAME_MAX_LENGTH = 64
MAGPIE_GROUP_NAME_MAX_LENGTH = 64

# ignore matches of settings and environment variables for following cases
MAGPIE_CONSTANTS = [
    "MAGPIE_CONSTANTS",
    "MAGPIE_ADMIN_PERMISSION",
    "MAGPIE_LOGGED_PERMISSION",
    "MAGPIE_CONTEXT_PERMISSION",
    "MAGPIE_LOGGED_USER",
    "MAGPIE_DEFAULT_PROVIDER",
    "MAGPIE_USER_NAME_MAX_LENGTH",
    "MAGPIE_GROUP_NAME_MAX_LENGTH",
    "MAGPIE_NETWORK_TOKEN_NAME",
    "MAGPIE_NETWORK_PROVIDER",
    "MAGPIE_NETWORK_NAME_PREFIX",
    "MAGPIE_NETWORK_GROUP_NAME"
]

# ===========================
# utilities
# ===========================

_REGEX_ASCII_ONLY = re.compile(r"\W|^(?=\d)")


def protected_user_name_regex(include_admin=True,
                              include_anonymous=True,
                              include_network=True,
                              additional_patterns=None,
                              settings_container=None):
    # type: (bool, bool, bool, Optional[List[Str]], Optional[AnySettingsContainer]) -> re.Pattern
    """
    Return a regular expression that matches all user names that are protected, meaning that they are generated
    by Magpie itself and no regular user account should be created with these user names.
    """
    patterns = additional_patterns or []
    if include_admin:
        patterns.append(get_constant("MAGPIE_ADMIN_USER", settings_container=settings_container))
    if include_anonymous:
        patterns.append(get_constant("MAGPIE_ANONYMOUS_USER", settings_container=settings_container))
    if include_network and network_enabled(settings_container=settings_container):
        patterns.append(
            "{}.*".format(get_constant("MAGPIE_NETWORK_NAME_PREFIX", settings_container=settings_container))
        )
    return re.compile("^({})$".format("|".join(patterns)))


def protected_user_email_regex(include_admin=True,
                               include_anonymous=True,
                               include_network=True,
                               additional_patterns=None,
                               settings_container=None):
    # type: (bool, bool, bool, Optional[List[Str]], Optional[AnySettingsContainer]) -> re.Pattern
    """
    Return a regular expression that matches all user emails that are protected, meaning that they are generated
    by Magpie itself and no regular user account should be created with these user emails.
    """
    patterns = additional_patterns or []
    if include_admin:
        patterns.append(get_constant("MAGPIE_ADMIN_EMAIL", settings_container=settings_container))
    if include_anonymous:
        patterns.append(get_constant("MAGPIE_ANONYMOUS_EMAIL", settings_container=settings_container))
    if include_network and network_enabled(settings_container=settings_container):
        email_form = get_constant("MAGPIE_NETWORK_ANONYMOUS_EMAIL_FORMAT", settings_container=settings_container)
        patterns.append(email_form.format(".*"))
    return re.compile("^({})$".format("|".join(patterns)))


def protected_group_name_regex(include_admin=True,
                               include_anonymous=True,
                               include_network=True,
                               settings_container=None):
    # type: (bool, bool, bool, Optional[AnySettingsContainer]) -> re.Pattern
    """
    Return a regular expression that matches all group names that are protected, meaning that they are generated
    by Magpie itself and no regular user account should be created with these group names.
    """
    patterns = []
    if include_admin:
        patterns.append(get_constant("MAGPIE_ADMIN_GROUP", settings_container=settings_container))
    if include_anonymous:
        patterns.append(get_constant("MAGPIE_ANONYMOUS_GROUP", settings_container=settings_container))
    if include_network and network_enabled(settings_container=settings_container):
        patterns.append(
            "{}.*".format(get_constant("MAGPIE_NETWORK_NAME_PREFIX", settings_container=settings_container))
        )
    return re.compile("^({})$".format("|".join(patterns)))


def network_enabled(settings_container=None):
    # type: (Optional[AnySettingsContainer]) -> bool
    if sys.version_info.major < 3 or sys.version_info.minor < 6:
        return False
    return bool(get_constant("MAGPIE_NETWORK_ENABLED", settings_container=settings_container))


def get_constant_setting_name(name):
    # type: (Str) -> Str
    """
    Find the equivalent setting name of the provided environment variable name.

    Lower-case name and replace all non-ascii chars by `_`.
    Then, convert known prefixes with their dotted name.
    """
    name = re.sub(_REGEX_ASCII_ONLY, "_", name.strip().lower())
    for prefix in ["magpie", "twitcher", "postgres", "phoenix"]:
        known_prefix = "{}_".format(prefix)
        dotted_prefix = "{}.".format(prefix)
        if name.startswith(known_prefix):
            return name.replace(known_prefix, dotted_prefix, 1)
    return name


def get_constant(constant_name,             # type: Str
                 settings_container=None,   # type: Optional[AnySettingsContainer]
                 settings_name=None,        # type: Optional[Str]
                 default_value=None,        # type: Optional[SettingValue]
                 raise_not_set=True,        # type: bool
                 raise_missing=True,        # type: bool
                 print_missing=False,       # type: bool
                 empty_missing=False,       # type: bool
                 ):                         # type: (...) -> SettingValue
    """
    Search in order for matched value of :paramref:`constant_name`:
      1. search in :py:data:`MAGPIE_CONSTANTS`
      2. search in settings if specified
      3. search alternative setting names (see below)
      4. search in :mod:`magpie.constants` definitions
      5. search in environment variables

    Parameter :paramref:`constant_name` is expected to have the format ``MAGPIE_[VARIABLE_NAME]`` although any value can
    be passed to retrieve generic settings from all above mentioned search locations.

    If :paramref:`settings_name` is provided as alternative name, it is used as is to search for results if
    :paramref:`constant_name` was not found. Otherwise, ``magpie.[variable_name]`` is used for additional search when
    the format ``MAGPIE_[VARIABLE_NAME]`` was used for :paramref:`constant_name`
    (i.e.: ``MAGPIE_ADMIN_USER`` will also search for ``magpie.admin_user`` and so on for corresponding constants).

    :param constant_name: key to search for a value
    :param settings_container: WSGI application settings container (if not provided, uses found one in current thread)
    :param settings_name: alternative name for `settings` if specified
    :param default_value: default value to be returned if not found anywhere, and exception raises are disabled.
    :param raise_not_set: raise an exception if the found key is ``None``, search until last case if others are ``None``
    :param raise_missing: raise exception if key is not found anywhere
    :param print_missing: print message if key is not found anywhere, return ``None``
    :param empty_missing: consider an empty value for an existing key as if it was missing (i.e.: as if not set).
    :returns: found value or `default_value`
    :raises ValueError: if resulting value is invalid based on options (by default raise missing/empty/``None`` value)
    :raises LookupError: if no appropriate value could be found from all search locations (according to options)
    """
    from magpie.utils import get_settings, print_log, raise_log  # pylint: disable=C0415  # avoid circular import error

    if constant_name in MAGPIE_CONSTANTS:
        return globals()[constant_name]
    missing = True
    magpie_value = None
    settings = get_settings(settings_container, app=True)
    if settings and constant_name in settings:  # pylint: disable=E1135
        missing = False
        magpie_value = settings.get(constant_name)
        if magpie_value is not None:
            if not empty_missing or magpie_value != "":
                print_log("Config found in settings with: {}".format(constant_name), level=logging.DEBUG)
                return magpie_value
            print_log("Constant ignored from settings (empty): {}".format(constant_name), level=logging.DEBUG)
    if not settings_name:
        settings_name = get_constant_setting_name(constant_name)
        print_log("Constant alternate search: {}".format(settings_name), level=logging.DEBUG)
    if settings and settings_name and settings_name in settings:  # pylint: disable=E1135
        missing = False
        magpie_value = settings.get(settings_name)
        if magpie_value is not None:
            if not empty_missing or magpie_value != "":
                print_log("Constant found in settings with: {}".format(settings_name), level=logging.DEBUG)
                return magpie_value
            print_log("Constant ignored from settings (empty): {}".format(settings_name), level=logging.DEBUG)
    magpie_globals = globals()
    if constant_name in magpie_globals:
        missing = False
        magpie_value = magpie_globals.get(constant_name)
        if magpie_value is not None:
            if not empty_missing or magpie_value != "":
                print_log("Constant found in definitions with: {}".format(constant_name), level=logging.DEBUG)
                return magpie_value
            print_log("Constant ignored from definition (empty): {}".format(constant_name), level=logging.DEBUG)
    if constant_name in os.environ:
        missing = False
        magpie_value = os.environ.get(constant_name)
        if magpie_value is not None:
            if not empty_missing or magpie_value != "":
                print_log("Constant found in environment with: {}".format(constant_name), level=logging.DEBUG)
                return magpie_value
            print_log("Constant ignored from environment (empty): {}".format(constant_name), level=logging.DEBUG)
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
