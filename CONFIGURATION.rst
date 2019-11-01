Configuration
=============

At startup, ``Magpie`` application will load multiple configuration files to define various behaviours or setup
operations. These are defined though the following configuration settings presented below.

All generic ``Magpie`` configuration settings can be defined through either the `<config/magpie.ini>`_ file or
environment variables. Values defined in `<config/magpie.ini>`_ are expected to follow the ``magpie.[variable_name]``
format, and corresponding ``MAGPIE_[VARIABLE_NAME]`` format is used for environment variables. Both of these
alternatives match the constants defined in `<magpie/constants.py>`_ and can be used interchangeably. Order of
resolution will prioritize setting values over environment variables in case of matching duplicates values.

Configuration Files
-------------------

magpie.ini
~~~~~~~~~~~~~~~~~~~

This is the base configuration file that defines most of ``Magpie``'s lower level configuration. A basic example is
provided in `<config/magpie.ini>`_ which should allow any user to run the application locally. Furthermore, this file
is used by default in each tagged Docker image. If you want to provide different configuration, the file should be
overridden in the Docker image using a volume mount parameter, or by specifying an alternative path through the
environment variable ``MAGPIE_INI_FILE_PATH``.

providers.cfg
~~~~~~~~~~~~~~~~~~~


permissions.cfg
~~~~~~~~~~~~~~~~~~~



magpie.env
~~~~~~~~~~~~~~~~~~~

By default, ``Magpie`` will try to load a ``magpie.env`` file which can define further environment variable definitions
used to setup the application (see ``MAGPIE_ENV_FILE`` setting further below). An example of expected format and common
variables for this file is presented in `<env/magpie.env.example>`_.

**Important Notes:**

If ``magpie.env`` cannot be found (using setting ``MAGPIE_ENV_FILE``) but ``magpie.env.example`` is available
(after resolving any previously set ``MAGPIE_ENV_DIR`` variable), this example file will be used to make a copy
saved as ``magpie.env`` and will be used as the base ``.env`` file to load its contained environment variables.
This behaviour is intended to reduce initial configuration and preparation of  ``Magpie`` for a new user.

When loading variables from the ``.env`` file, any conflicting environment variable will **NOT** be overridden.
Therefore, only *missing but required* values will be added to the environment to ensure proper setup of ``Magpie``.

postgres.env
~~~~~~~~~~~~~~~~~~~

This file behaves exactly in the same manner as for ``magpie.env`` above, but for specific variables definition
employed to setup the `postgres` database connection (see ``MAGPIE_POSTGRES_ENV_FILE`` setting below).
File `<env/postgres.env.example>`_ and auto-resolution of missing ``postgres.env`` is identical to ``magpie.env`` case.

Settings and Constants
----------------------

Environment variables can be used to define all following settings (unless mentioned otherwise with 'constant').
These values will be used by ``Magpie`` on startup unless prior definition is found within `<config/magpie.ini>`_.

Base Settings
~~~~~~~~~~~~~

These settings can be used to specify where to find other settings through custom configuration files.

- | ``MAGPIE_MODULE_DIR`` (constant)
  | Path to the top level ``Magpie`` module (ie: source code).

- | ``MAGPIE_ROOT`` (constant)
  | Path to the containing directory of ``Magpie``. This corresponds to the directory where the repository was cloned
    or where the package was installed.

- | ``MAGPIE_CONFIG_DIR``
  | Configuration directory where to look for ``providers.cfg`` and ``permissions.cfg`` files.
  | (Default: ``${MAGPIE_ROOT}/config``)

- | ``MAGPIE_PROVIDERS_CONFIG_PATH``
  | Path where to find ``providers.cfg`` file. Can also be a directory path, where all contained ``.cfg`` files will
    be considered as `providers` files and will be loaded sequentially. \
    Please refer to `<config/providers.cfg>`_ for specific format details.
  | (Default: ``${MAGPIE_CONFIG_DIR}/providers.cfg``)

- | ``MAGPIE_PERMISSIONS_CONFIG_PATH``
  | Path where to find ``permissions.cfg`` file. Can also be a directory path, where all contained ``.cfg`` files will
    be considered as `permissions` files and will be loaded sequentially. \
    Please refer to `<config/permissions.cfg>`_ for specific format details.
  | (default: ``${MAGPIE_CONFIG_DIR}/permissions.cfg``)

- | ``MAGPIE_INI_FILE_PATH``
  | Specifies where to find the initialization file to run ``Magpie`` application.
  | **Note**: this variable ignores the setting/env-var resolution order since settings cannot be defined without
              firstly loading the file referenced by its value.

- | ``MAGPIE_ALEMBIC_INI_FILE_PATH``
  | Path to ``.ini`` file which defines an ``[alembic]`` section specifying details on how to execute database
    migration operations.
  | (Default: ``${MAGPIE_INI_FILE_PATH}``) [section defined within `<config/magpie.ini>`_]

- | ``MAGPIE_ENV_DIR``
  | Directory path where to look for ``.env`` files. This variable can be useful to load specific test environment
    configurations or to specify a local path while the actual ``Magpie`` code is located in a Python `site-packages`
    directory (``.env`` files are not installed to avoid hard-to-resolve settings loaded from an install location).
  | (Default: ``${MAGPIE_ROOT}/env``)

- | ``MAGPIE_ENV_FILE``
  | File path to ``magpie.env`` file with additional environment variables to configure the application.
  | (Default: ``${MAGPIE_ENV_DIR}/magpie.env``)

- | ``MAGPIE_POSTGRES_ENV_FILE``
  | File path to ``postgres.env`` file with additional environment variables to configure the `postgres` connection.
  | (Default: ``${MAGPIE_ENV_DIR}/postgres.env``)

Application Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings are used to define values that are employed by ``Magpie`` after loading the `Base Settings`_.

- | ``
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

Postgres Settings
~~~~~~~~~~~~~~~~~~~~~

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

External Providers
----------------------

In order to perform authentication in ``Magpie``, multiple external providers are supported. By default, the 'local'
provider is ``ziggurat`` which corresponds to the package used to manage users, groups, permissions, etc. internally.
Supported external providers are presented in the table below, although more could be added later on. 

Each as different configuration parameters as defined in `<magpie/security.py>`_ and use various protocols amongst
``OpenID``, ``ESGF``-flavored ``OpenID`` and ``OAuth2``. Further external providers can be defined using this module's
dictionary configuration style following parameter specification of `Authomatic`_ package used for managing this
authentication procedure.

+----------------------------------------------------+-----------------------------------------------------------------------+
| Category                                           | Provider                                                              |
+====================================================+=======================================================================+
| Open Identity (``OpenID``)                         | `OpenID`_                                                             |
+----------------------------------------------------+-----------------------------------------------------------------------+
| Earth System Grid Federation (`ESGF`_) :sup:`(1)`  | German Climate Computing Centre (`DKRZ`_)                             |
|                                                    +-----------------------------------------------------------------------+
|                                                    | French Research Institute for Environment Science (`IPSL`_)           |
|                                                    +-----------------------------------------------------------------------+
|                                                    | British Centre for Environmental Data Analysis (`CEDA`_) :sup:`(2)`   |
|                                                    +-----------------------------------------------------------------------+
|                                                    | US Lawrence Livermore National Laboratory (`LLNL`_) :sup:`(3)`        |
|                                                    +-----------------------------------------------------------------------+
|                                                    | Swedish Meteorological and Hydrological Institute (`SMHI`_)           |
+----------------------------------------------------+-----------------------------------------------------------------------+
| ``OAuth2``                                         | `GitHub`_ Authentication                                              |
|                                                    +-----------------------------------------------------------------------+
|                                                    | `WSO2`_ Open Source Identity Server                                   |
+----------------------------------------------------+-----------------------------------------------------------------------+

| :sup:`(1)` extended variant of ``OpenID``
| :sup:`(2)` formerly identified as British Atmospheric Data Centre (`BADC`_)
| :sup:`(3)` formerly identified as Program for Climate Model Diagnosis & Intercomparison (`PCMDI`_)

| **Note:**
| Please note that due to the constantly changing nature of multiple of these external providers (APIs and moved 
  Websites), rarely used authentication bridges by the developers could break without prior notice. If this is the
  case and you use one of the broken connectors, summit a new `issue <MagpieIssue>`_.

.. _Authomatic: https://authomatic.github.io/authomatic/
.. _OpenID: https://openid.net/
.. _ESGF: https://esgf.llnl.gov/
.. _DKRZ: https://esgf-data.dkrz.de
.. _IPSL: https://www.ipsl.fr/
.. _BADC: http://data.ceda.ac.uk/badc
.. _CEDA: https://esgf-index1.ceda.ac.uk
.. _LLNL: https://www.llnl.gov/
.. _PCMDI: https://pcmdi.llnl.gov/?esgcet/home
.. _SMHI: https://www.smhi.se
.. _GitHub: https://developer.github.com/v3/#authentication
.. _WSO2: https://wso2.com/
.. _MagpieIssues: https://github.com/Ouranosinc/Magpie/issues/new

GitHub Settings
~~~~~~~~~~~~~~~~~



WSO2 Settings
~~~~~~~~~~~~~~~~~


