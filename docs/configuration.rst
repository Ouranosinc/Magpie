Configuration
=============

At startup, `Magpie` application will load multiple configuration files to define various behaviours or setup
operations. These are defined though the following configuration settings presented below.

All generic `Magpie` configuration settings can be defined through either the `magpie.ini`_ file
or environment variables. Values defined in `magpie.ini`_ are expected to follow the
``magpie.[variable_name]`` format, and corresponding ``MAGPIE_[VARIABLE_NAME]`` format is used for environment
variables. Both of these alternatives match the constants defined in `constants.py`_ and can be used
interchangeably. Order of resolution will prioritize setting values over environment variables in case of duplicate
configurations resulting into different values.

.. _constants.py: ../magpie/constants.py

Configuration Files
-------------------

File: magpie.ini
~~~~~~~~~~~~~~~~~~~

This is the base configuration file that defines most of `Magpie`'s lower level configuration. A basic example is
provided in `magpie.ini`_ which should allow any user to run the application locally. Furthermore, this file
is used by default in each tagged Docker image. If you want to provide different configuration, the file should be
overridden in the Docker image using a volume mount parameter, or by specifying an alternative path through the
environment variable ``MAGPIE_INI_FILE_PATH``.

File: providers.cfg
~~~~~~~~~~~~~~~~~~~

This configuration file allows automatically registering service definitions in `Magpie` at startup. When the
application starts, it will look for corresponding services and add them to the database as required. It will also
look for mismatches between the service name and URL with the corresponding entry in the database to update it to
the desired URL. See ``MAGPIE_PROVIDERS_CONFIG_PATH`` below to setup alternate references to this type of configuration.
Please refer to the heading of sample file `providers.cfg`_ for specific format and parameter details.

File: permissions.cfg
~~~~~~~~~~~~~~~~~~~~~~

This configuration file allows automatically registering or cleaning permission definitions in `Magpie` at startup.
Each specified permission update operation is applied for the corresponding user or group onto the specific service
or resource. This file is processed after `providers.cfg`_ in order to allow permissions to be applied on freshly
registered services. Furthermore, sub-resources are automatically created if they can be resolved with provided
parameters of the corresponding permission entry. See ``MAGPIE_PERMISSIONS_CONFIG_PATH`` below to setup alternate
references to this type of configuration. Please refer to the heading of sample file `permissions.cfg`_ for specific
format details as well as specific behaviour of each parameter according to encountered use cases.

File: magpie.env
~~~~~~~~~~~~~~~~~~~

By default, `Magpie` will try to load a ``magpie.env`` file which can define further environment variable definitions
used to setup the application (see ``MAGPIE_ENV_FILE`` setting further below). An example of expected format and common
variables for this file is presented in `magpie.env.example`_.

**Important Notes:**

If ``magpie.env`` cannot be found (using setting ``MAGPIE_ENV_FILE``) but ``magpie.env.example`` is available
(after resolving any previously set ``MAGPIE_ENV_DIR`` variable), this example file will be used to make a copy
saved as ``magpie.env`` and will be used as the base ``.env`` file to load its contained environment variables.
This behaviour is intended to reduce initial configuration and preparation of  `Magpie` for a new user.

When loading variables from the ``.env`` file, any conflicting environment variable will **NOT** be overridden.
Therefore, only *missing but required* values will be added to the environment to ensure proper setup of `Magpie`.

.. _magpie.env.example: ../env/magpie.env.example

File: postgres.env
~~~~~~~~~~~~~~~~~~~

This file behaves exactly in the same manner as for ``magpie.env`` above, but for specific variables definition
employed to setup the `postgres` database connection (see ``MAGPIE_POSTGRES_ENV_FILE`` setting below).
File `postgres.env.example`_ and auto-resolution of missing ``postgres.env`` is identical to ``magpie.env``
case.

.. _postgres.env.example: ../env/postgres.env.example

Settings and Constants
----------------------

Environment variables can be used to define all following configurations (unless mentioned otherwise with
``[constant]`` keyword next to the parameter name).
These values will be used by `Magpie` on startup unless prior definition is found within `magpie.ini`_.
All variables (i.e.: non-``constant`` parameters) can also be specified by their ``magpie.[variable_name]``
counterpart as described at the start of the `Configuration`_ section.

Loading Settings
~~~~~~~~~~~~~~~~~

These settings can be used to specify where to find other settings through custom configuration files.

- | ``MAGPIE_MODULE_DIR`` [constant]
  | Path to the top level `Magpie` module (ie: source code).

- | ``MAGPIE_ROOT`` [constant]
  | Path to the containing directory of `Magpie`. This corresponds to the directory where the repository was cloned
    or where the package was installed.

- | ``MAGPIE_CONFIG_DIR``
  | Configuration directory where to look for ``providers.cfg`` and ``permissions.cfg`` files.
  | (Default: ``${MAGPIE_ROOT}/config``)

- | ``MAGPIE_PROVIDERS_CONFIG_PATH``
  | Path where to find ``providers.cfg`` file. Can also be a directory path, where all contained ``.cfg`` files will
    be considered as `providers` files and will be loaded sequentially.
  | **Note**:
  | If a directory path is specified, the order of loaded configuration files is not guaranteed
    (depending on OS implementation).
  | Please refer to `providers.cfg`_ for specific format details and loading methodology according to arguments.
  | (Default: ``${MAGPIE_CONFIG_DIR}/providers.cfg``)

- | ``MAGPIE_PERMISSIONS_CONFIG_PATH``
  | Path where to find ``permissions.cfg`` file. Can also be a directory path, where all contained ``.cfg`` files will
    be considered as `permissions` files and will be loaded sequentially.
  | **Note**:
  | If a directory path is specified, the order of loaded configuration files is not guaranteed
    (depending on OS implementation). Therefore, cross-file references to services or resources should be avoided
    to ensure that, for example, any parent resource dependency won't be missing because it was specified in a second
    file loaded after the first. Corresponding references can be duplicated across files and these conflicts will be
    correctly handled according to configuration loading methodology.
  | Please refer to `permissions.cfg`_ for specific format details and loading methodology according to arguments.
  | (default: ``${MAGPIE_CONFIG_DIR}/permissions.cfg``)

- | ``MAGPIE_INI_FILE_PATH``
  | Specifies where to find the initialization file to run `Magpie` application.
  | **Note**:
  | This variable ignores the setting/env-var resolution order since settings cannot be defined without
    firstly loading the file referenced by its value.

- | ``MAGPIE_ENV_DIR``
  | Directory path where to look for ``.env`` files. This variable can be useful to load specific test environment
    configurations or to specify a local path while the actual `Magpie` code is located in a Python `site-packages`
    directory (``.env`` files are not installed to avoid hard-to-resolve settings loaded from an install location).
  | (Default: ``${MAGPIE_ROOT}/env``)

- | ``MAGPIE_ENV_FILE``
  | File path to ``magpie.env`` file with additional environment variables to configure the application.
  | (Default: ``${MAGPIE_ENV_DIR}/magpie.env``)

- | ``MAGPIE_POSTGRES_ENV_FILE``
  | File path to ``postgres.env`` file with additional environment variables to configure the `postgres` connection.
  | (Default: ``${MAGPIE_ENV_DIR}/postgres.env``)


.. _magpie.ini: ../config/magpie.ini
.. _permissions.cfg: ../config/permissions.cfg
.. _providers.cfg: ../config/permissions.cfg

Application Settings
~~~~~~~~~~~~~~~~~~~~~

Following configuration parameters are used to define values that are employed by `Magpie` after loading
the `Loading Settings`_. All ``magpie.[variable_name]`` counterpart definitions are also available as described
at the start of the `Configuration`_ section.

- | ``MAGPIE_URL``
  | Full hostname URL to use so that `Magpie` can resolve his own running instance location.
  | **Note:**
  | If the value is not set, `Magpie` will attempt to retrieve this critical information through other variables such
    as ``MAGPIE_HOST``, ``MAGPIE_PORT``, ``MAGPIE_SCHEME`` and ``HOSTNAME``. Modifying any of these variables
    partially is permitted but will force `Magpie` to attempt building the full URL as best as possible from the
    individual parts. The result of these parts (potential using corresponding defaults) will have the following format:
    ``"${MAGPIE_SCHEME}//:${MAGPIE_HOST}:${MAGPIE_PORT}"``.
  | (Default: ``"http://localhost:2001"``)

- | ``MAGPIE_SCHEME``
  | Protocol scheme URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.
  | (Default: ``"http"``)

- | ``MAGPIE_HOST``
  | Domain host URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.
  | (Default: ``"localhost"``)

- | ``MAGPIE_PORT``
  | Port URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.
  | (Default: ``2001``)

- | ``MAGPIE_SECRET``
  | Port URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.
  | (Default: ``2001``)

- | ``MAGPIE_CRON_LOG``
  | Path that the ``cron`` operation should use for logging.
  | (Default: ``"~/magpie-cron.log"``)

- | ``MAGPIE_LOG_LEVEL``
  | Logging level of operations. `Magpie` will first use the complete logging configuration found in
    `magpie.ini`_ in order to define logging formatters and handler referencing to the ``logger_magpie``
    section. If this configuration fail to retrieve an explicit logging level, this variable is used instead to
    prepare a basic logger, after checking if a corresponding ``magpie.log_level`` setting was instead specified.
  | (Default: ``INFO``)

- | ``MAGPIE_LOG_LEVEL``
  | Specifies whether `Magpie` logging should also enforce printing the details to the console when using *helpers*.
    Otherwise, the configured logging methodology in `magpie.ini`_ is used (which can also define a
    console handler).
  | (Default: ``False``)

- | ``MAGPIE_LOG_REQUEST``
  | Specifies whether `Magpie` should log incoming request details.
  | **Note:**
  | This can make `Magpie` quite verbose if large quantity of requests are accomplished.
  | (Default: ``True``)

- | ``MAGPIE_LOG_EXCEPTION``
  | Specifies whether `Magpie` should log a raised exception during a process execution.
  | (Default: ``True``)

- | ``MAGPIE_UI_ENABLED``
  | Specifies whether `Magpie` graphical user interface should be available with the started instance. If disabled,
    all routes that normally refer to the UI will return ``404``, except the frontpage that will return a simple JSON
    description as it is normally the default entrypoint of the application.
  | (Default: ``True``)


Security Settings
~~~~~~~~~~~~~~~~~~~~~

Following configuration parameters are used to define specific values that are related to security configurations.
Again, the `Loading Settings`_ will be processed beforehand and all ``magpie.[variable_name]`` setting definitions
remain available as described at the start of the `Configuration`_ section.

- | ``MAGPIE_SECRET``
  | Secret value employed to encrypt user authentication tokens.
  | **Important Note:**
  | Changing this value at a later time will cause previously created user tokens to be invalidated.
    It is **strongly** recommended to change this value before proceeding to user accounts and permissions creation
    in your `Magpie` instance.
  | (Default: ``"seekrit"``)

- | ``MAGPIE_COOKIE_NAME``
  | Identifier of the cookie that will be used for reading and writing in the requests from login and for
    user authentication operations.
  | (Default: ``"auth_tkt"``)

- | ``MAGPIE_COOKIE_EXPIRE``
  | Lifetime duration of the cookies. Tokens become invalid after this duration is elapsed.
  | (Default: ``None`` [infinite])

- | ``MAGPIE_ADMIN_USER``
  | Name of the default 'administrator' generated by the application.
  | **Note:**
  | This user is required for initial launch of the application to avoid being 'looked out' as routes for creating new
    users require administrative permissions and access rights. It should be used as a first login method to setup other
    accounts. It will also be used by other `Magpie` internal operations such as service synchronization and setup
    during the application startup. If this user is missing, it is automatically re-created on following start.
  | (Default: ``"admin"``)

- | ``MAGPIE_ADMIN_PASSWORD``
  | Password of the default 'administrator' generated by the application.
  | (Default: ``"qwerty"``)

- | ``MAGPIE_ADMIN_EMAIL``
  | Email of the default 'administrator' generated by the application.
  | (Default: ``"${MAGPIE_ADMIN_USER}@mail.com"``)

- | ``MAGPIE_ADMIN_GROUP``
  | Group name of the default 'administrator' generated by the application.
  | **Note:**
  | To simplify configuration of future administrators of the application, all their inherited permissions are shared
    through this group instead of setting individual permissions on each user. It is recommended to keep defining such
    higher level permissions on this group to ease the management process of granted access to all their members.
  | (Default: ``"administrators"``)

- | ``MAGPIE_ADMIN_PERMISSION``
  | Name of the permission used to represent highest administration privilege in the application.
  | Except for some public routes, most API and UI paths will require the user to have this permission (either with
    direct permission or by inherited group permission) to be granted access to view and edit content.
    The group defined by ``MAGPIE_ADMIN_GROUP`` automatically gets granted this permission.
  | (Default: ``"admin"``)

- | ``MAGPIE_ANONYMOUS_USER``
  | Name of the default user that represents a non logged-in user (ie: invalid or no authentication token provided).
  | This user is used to manage "public" access to service and resources.
  | (Default: ``"anonymous"``)

- | ``MAGPIE_ANONYMOUS_PASSWORD`` [constant]
  | Password of the default unauthenticated user.
  | This value is not modifiable directly and is available only for preparation of the default user on startup.
  | (Default: ``${MAGPIE_ANONYMOUS_USER}``)

- | ``MAGPIE_ANONYMOUS_EMAIL``
  | Email of the default unauthenticated user.
  | (Default: ``"${MAGPIE_ANONYMOUS_USER}@mail.com"``)

- | ``MAGPIE_ANONYMOUS_GROUP`` [constant]
  | This parameter is preserved for backward compatibility of migration scripts and external libraries.
  | All users are automatically member of this group to inherit "public" permissions to services and resources.
  | **Important Note:**
  | To set "public" permissions, one should always set them on this group instead of directly on
    ``MAGPIE_ANONYMOUS_USER`` as setting them directly on this user will cause only him to be granted access to the
    targeted resource. In this situation, all *other* users would "lose" public permissions after they authenticate
    themselves in `Magpie` as they would not be recognized as ``MAGPIE_ANONYMOUS_USER`` anymore.
  | (Default: ``${MAGPIE_ANONYMOUS_USER}``)

- | ``MAGPIE_EDITOR_GROUP``
  | *Unused for the moment.*
  | (Default: ``"editors"``)

- | ``MAGPIE_USERS_GROUP``
  | Name of the default group created to associate all users registered in the application.
  | New users are created with this group.
  | (Default: ``"users"``)

- | ``MAGPIE_USER_NAME_MAX_LENGTH``
  | Maximum length to consider as a valid user name. User name specified during creation will be forbidden if longer.
  | **Note:**
  | This value should not be greater then the token length used to identify a user to preserve some utility behaviour.
  | (Default: ``64``)

- | ``MAGPIE_LOGGED_USER``
  | Keyword used to define route resolution using the currently logged in user. This value allows, for example,
    retrieving the user details of the logged user with ``GET /users/${MAGPIE_LOGGED_USER}`` instead of having to
    find explicitly the ``GET /users/<my-user-id>`` variant. User resolution is done using the authentication cookie
    found in the request. If no cookie can be found, it defaults to the ``MAGPIE_ANONYMOUS_USER`` value.
  | **Note:**
  | Because the user executing the request with this keyword is effectively the authenticated user, the behaviour of
    some specific paths can be slightly different than their literal user-id counterpart. For example, user details
    will be accessible to the logged user (he can view his own information) but this same user will receive an
    unauthorized response if using is ID in the path if he doesn't have administrator privilege.
  | (Default: ``"current"``)

- | ``MAGPIE_DEFAULT_PROVIDER``
  | Name of the provider used for local login. This represents the identifier that will be set to define who to
    differentiate between a local sign-in procedure and a dispatched one to one of the known `External Providers`_.
  | *The default is the value of the internal package used to manage user permissions.*
  | (Default: ``"ziggurat"``)

Phoenix Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings provide some integration support for `Phoenix`_ in order to synchronize its service definitions with
`Magpie` services.

| **Note:**
| Support of `Phoenix`_ is fairly minimal.
| Please submit an issue if you use it and some unexpected behaviour is encountered.

- | ``PHOENIX_USER``
  | Name of the user to use for authentication in `Phoenix`_.
  | (Default: ``"phoenix"``)

- | ``PHOENIX_PASSWORD``
  | Password of the user to use for authentication in `Phoenix`_.
  | (Default: ``"qwerty"``)

- | ``PHOENIX_HOST``
  | Hostname to use for `Phoenix`_ connection for authentication and service synchronization.
  | (Default: ``${HOSTNAME}"``)

- | ``PHOENIX_PORT``
  | Port to use for `Phoenix`_ connection for authentication and service synchronization.
  | (Default: ``8443``)

- | ``PHOENIX_PUSH``
  | Whether to push new service synchronization settings to the referenced `Phoenix`_ connection.
  | (Default: ``True``)

.. _Phoenix: https://github.com/bird-house/pyramid-phoenix


Twitcher Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings define parameters required by `Twitcher`_ (OWS Security Proxy) in order to interact with
`Magpie` services.

- | ``TWITCHER_PROTECTED_PATH``
  | HTTP path used to define the protected (public) base path of services registered in `Magpie` that will be served by
    an existing `Twitcher`_ proxy application after Access Control List (ACL) verification of the authenticated user.
  | **Note:**
  | Using this parameter to define `Twitcher`_'s path assumes that it resides under the same server domain as the
    `Magpie` instance being configured (ie: hostname is inferred from resolved ``MAGPIE_URL`` or equivalent settings).
  | (Default: ``"/ows/proxy"``)

- | ``TWITCHER_PROTECTED_URL``
  | Defines the protected (public) full base URL of services registered in `Magpie`. This setting is mainly to allow
    specifying an alternative domain where a remote `Twitcher`_ instance could reside.
  | **Note:**
  | `Twitcher`_ instance will still need to have access to `Magpie`'s database in order to allow service resolution
    with `magpie.adapter.magpieservice.MagpieServiceStore`.
  | (Default: ``None``, ie: uses ``TWITCHER_PROTECTED_PATH``)

.. _Twitcher: https://github.com/bird-house/twitcher


Postgres Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings define parameters required to define the `Postgres`_ database connection employed by `Magpie` as
well as some other database-related operation settings. Settings defined by ``magpie.[variable_name]`` definitions
are available as described at the start of the `Configuration`_ section, as well as some special cases where additional
configuration names are supported where mentioned.

- | ``MAGPIE_DB_MIGRATION``
  | Run database migration on startup in order to bring it up to date using `Alembic`_.
  | (Default: ``True``)

- | ``MAGPIE_DB_MIGRATION_ATTEMPTS``
  | Number of attempts to re-run database migration on startup in cased it failed (eg: due to connection error).
  | (Default: ``5``)

- | ``MAGPIE_DB_URL``
  | Full database connection URL formatted as ``<db-type>://<user>:<password>@<host>:<port>/<db-name>``.
  | Please refer to `SQLAlchemy Engine`_'s documentation for supported database implementations and their corresponding
    configuration. Only `Postgres`_ has been extensively tested with `Magpie`, but other variants should be applicable.
  | (Default: infer ``postgresql`` database connection URL formed using below ``MAGPIE_POSTGRES_<>`` parameters if the
     value was not explicitly provided)

- | ``MAGPIE_POSTGRES_USERNAME``
  | Database connection username to retrieve `Magpie` data stored in `Postgres`_.
  | On top of ``MAGPIE_POSTGRES_USERNAME``, environment variable ``POSTGRES_USERNAME`` and setting ``postgres.username``
    are also supported. For backward compatibility, all above variants with ``user`` instead of ``username``
    (with corresponding lower/upper case) are also verified for potential configuration if no prior parameter was
    matched. The lookup order of each name variant is as they were presented, while also keeping the setting name
    priority over an equivalent environment variable name.
  | (Default: ``"magpie"``)

- | ``MAGPIE_POSTGRES_PASSWORD``
  | Database connection password to retrieve `Magpie` data stored in `Postgres`_.
  | Environment variable ``POSTGRES_PASSWORD`` and setting ``postgres.password`` are also supported if not previously
    identified by their `Magpie`-prefixed variants.
  | (Default: ``"qwerty"``)

- | ``MAGPIE_POSTGRES_HOST``
  | Database connection host location to retrieve `Magpie` data stored in `Postgres`_.
  | Environment variable ``POSTGRES_HOST`` and setting ``postgres.host`` are also supported if not previously
    identified by their `Magpie`-prefixed variants.
  | (Default: ``"postgres"``)

- | ``MAGPIE_POSTGRES_PORT``
  | Database connection port to retrieve `Magpie` data stored in `Postgres`_.
  | Environment variable ``POSTGRES_PORT`` and setting ``postgres.port`` are also supported if not previously
    identified by their `Magpie`-prefixed variants.
  | (Default: ``5432``)

- | ``MAGPIE_POSTGRES_DB``
  | Name of the database located at the specified connection to retrieve `Magpie` data stored in `Postgres`_.
  | Environment variable ``POSTGRES_DB`` and setting ``postgres.db``, as well as the same variants with ``database``
    instead of ``db``, are also supported if not previously identified by their `Magpie`-prefixed variants.
  | (Default: ``"magpie"``)

.. _Postgres: https://www.postgresql.org/
.. _Alembic: https://alembic.sqlalchemy.org/
.. _SQLAlchemy Engine: https://docs.sqlalchemy.org/en/13/core/engines.html


External Providers
----------------------

In order to perform authentication in `Magpie`, multiple external providers are supported. By default, the 'local'
provider is ``ziggurat`` which corresponds to the package used to manage users, groups, permissions, etc. internally.
Supported external providers are presented in the table below, although more could be added later on.

Each as different configuration parameters as defined in `MagpieSecurity`_ and use various protocols amongst
``OpenID``, ``ESGF``-flavored ``OpenID`` and ``OAuth2``. Further external providers can be defined using this module's
dictionary configuration style following parameter specification of `Authomatic`_ package used for managing this
authentication procedure.

+--------------------------------+-----------------------------------------------------------------------+
| Category                       | Provider                                                              |
+================================+=======================================================================+
| Open Identity (``OpenID``)     | `OpenID`_                                                             |
+--------------------------------+-----------------------------------------------------------------------+
| *Earth System Grid Federation* | *German Climate Computing Centre* (`DKRZ`_)                           |
| (`ESGF`_) :sup:`(1)`           |                                                                       |
|                                +-----------------------------------------------------------------------+
|                                | *French Research Institute for Environment Science* (`IPSL`_)         |
|                                +-----------------------------------------------------------------------+
|                                | *British Centre for Environmental Data Analysis* (`CEDA`_) :sup:`(2)` |
|                                +-----------------------------------------------------------------------+
|                                | *US Lawrence Livermore National Laboratory* (`LLNL`_) :sup:`(3)`      |
|                                +-----------------------------------------------------------------------+
|                                | *Swedish Meteorological and Hydrological Institute* (`SMHI`_)         |
+--------------------------------+-----------------------------------------------------------------------+
| ``OAuth2``                     | `GitHub`_ Authentication                                              |
|                                +-----------------------------------------------------------------------+
|                                | `WSO2`_ Open Source Identity Server                                   |
+--------------------------------+-----------------------------------------------------------------------+

| :sup:`(1)` extended variant of ``OpenID``
| :sup:`(2)` formerly identified as *British Atmospheric Data Centre* (`BADC`_)
| :sup:`(3)` formerly identified as *Program for Climate Model Diagnosis & Intercomparison* (`PCMDI`_)

| **Note:**
| Please note that due to the constantly changing nature of multiple of these external providers (APIs and moved
  Websites), rarely used authentication bridges by the developers could break without prior notice. If this is the
  case and you use one of the broken connectors, summit a new
  `issue <https://github.com/Ouranosinc/Magpie/issues/new>`_.

.. _Authomatic: https://authomatic.github.io/authomatic/
.. _OpenID: https://openid.net/
.. _ESGF: https://esgf.llnl.gov/
.. _DKRZ: https://esgf-data.dkrz.de
.. _IPSL: https://www.ipsl.fr/
.. _BADC: http://data.ceda.ac.uk/badc
.. _CEDA: https://esgf-index1.ceda.ac.uk
.. _LLNL: https://www.llnl.gov/
.. _PCMDI: http://pcmdi.llnl.gov
.. _SMHI: https://www.smhi.se
.. _GitHub: https://developer.github.com/v3/#authentication
.. _WSO2: https://wso2.com/
.. _MagpieSecurity: ../magpie/security.py

GitHub Settings
~~~~~~~~~~~~~~~~~

To use `GitHub`_ authentication provider, variables ``GITHUB_CLIENT_ID`` and ``GITHUB_CLIENT_SECRET`` must be
configured. These settings correspond to the values retrieved from following steps described in
`Creating an OAuth App`_.

Furthermore, the callback URL used for configuring the OAuth application on Github must match the running `Magpie`
instance URL. For this reason, the values of ``MAGPIE_URL``, ``MAGPIE_HOST`` and ``HOSTNAME`` must be considered.

.. _Creating an OAuth App: https://developer.github.com/apps/building-oauth-apps/creating-an-oauth-app/

WSO2 Settings
~~~~~~~~~~~~~~~~~

To use `WSO2`_ authentication provider, following variables must be set:

- ``WSO2_HOSTNAME``
- ``WSO2_CLIENT_ID``
- ``WSO2_CLIENT_SECRET``
- ``WSO2_CERTIFICATE_FILE``
- ``WSO2_SSL_VERIFY``

To configure your `Magpie` instance as a trusted application for ``WSO2`` (and therefore retrieve values of above
parameters), please refer to `WSO2 Identity Server Documentation`_.


.. _WSO2 Identity Server Documentation: https://docs.wso2.com/display/IS550/WSO2+Identity+Server+Documentation
