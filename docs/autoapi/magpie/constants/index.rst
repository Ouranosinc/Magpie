:mod:`magpie.constants`
=======================

.. py:module:: magpie.constants

.. autoapi-nested-parse::

   Constant settings for Magpie application.

   Constants defined with format ``MAGPIE_[VARIABLE_NAME]`` can be matched with corresponding
   settings formatted as ``magpie.[variable_name]`` in the ``magpie.ini`` configuration file.

   .. note::
       Since the ``magpie.ini`` file has to be loaded by the application to retrieve various configuration settings,
       constant ``MAGPIE_INI_FILE_PATH`` (or any other `path variable` defined before it - see below) has to be defined
       by environment variable if the default location is not desired (ie: if you want to provide your own configuration).



Module Contents
---------------

.. data:: MAGPIE_MODULE_DIR
   

   

.. data:: MAGPIE_ROOT
   

   

.. data:: MAGPIE_CONFIG_DIR
   

   

.. data:: MAGPIE_PROVIDERS_CONFIG_PATH
   

   

.. data:: MAGPIE_PERMISSIONS_CONFIG_PATH
   

   

.. data:: MAGPIE_INI_FILE_PATH
   

   

.. data:: MAGPIE_ALEMBIC_INI_FILE_PATH
   

   

.. data:: MAGPIE_ENV_DIR
   

   

.. data:: MAGPIE_ENV_FILE
   

   

.. data:: MAGPIE_POSTGRES_ENV_FILE
   

   

.. data:: magpie_env_example
   

   

.. data:: postgres_env_example
   

   

.. function:: _get_default_log_level()
   Get default configurations from ini file.


.. data:: MAGPIE_URL
   

   

.. data:: MAGPIE_SECRET
   

   

.. data:: MAGPIE_COOKIE_NAME
   

   

.. data:: MAGPIE_COOKIE_EXPIRE
   

   

.. data:: MAGPIE_ADMIN_USER
   

   

.. data:: MAGPIE_ADMIN_PASSWORD
   

   

.. data:: MAGPIE_ADMIN_EMAIL
   

   

.. data:: MAGPIE_ADMIN_GROUP
   

   

.. data:: MAGPIE_ANONYMOUS_USER
   

   

.. data:: MAGPIE_ANONYMOUS_PASSWORD
   

   

.. data:: MAGPIE_ANONYMOUS_EMAIL
   

   

.. data:: MAGPIE_ANONYMOUS_GROUP
   

   

.. data:: MAGPIE_EDITOR_GROUP
   

   

.. data:: MAGPIE_USERS_GROUP
   

   

.. data:: MAGPIE_CRON_LOG
   

   

.. data:: MAGPIE_DB_MIGRATION
   

   

.. data:: MAGPIE_DB_MIGRATION_ATTEMPTS
   

   

.. data:: MAGPIE_LOG_LEVEL
   

   

.. data:: MAGPIE_LOG_PRINT
   

   

.. data:: MAGPIE_LOG_REQUEST
   

   

.. data:: MAGPIE_LOG_EXCEPTION
   

   

.. data:: MAGPIE_UI_ENABLED
   

   

.. data:: PHOENIX_USER
   

   

.. data:: PHOENIX_PASSWORD
   

   

.. data:: PHOENIX_HOST
   

   

.. data:: PHOENIX_PORT
   

   

.. data:: PHOENIX_PUSH
   

   

.. data:: TWITCHER_PROTECTED_PATH
   

   

.. data:: TWITCHER_PROTECTED_URL
   

   

.. data:: MAGPIE_POSTGRES_USER
   

   

.. data:: MAGPIE_POSTGRES_PASSWORD
   

   

.. data:: MAGPIE_POSTGRES_HOST
   

   

.. data:: MAGPIE_POSTGRES_PORT
   

   

.. data:: MAGPIE_POSTGRES_DB
   

   

.. data:: MAGPIE_ADMIN_PERMISSION
   :annotation: = admin

   

.. data:: MAGPIE_LOGGED_USER
   :annotation: = current

   

.. data:: MAGPIE_DEFAULT_PROVIDER
   :annotation: = ziggurat

   

.. data:: MAGPIE_USER_NAME_MAX_LENGTH
   :annotation: = 64

   

.. data:: _REGEX_ASCII_ONLY
   

   

.. function:: get_constant_setting_name(name)
   Lower-case name and replace all non-ascii chars by `_`.


.. function:: get_constant(constant_name, settings_container=None, settings_name=None, default_value=None, raise_missing=True, print_missing=False, raise_not_set=True) -> SettingValue
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


