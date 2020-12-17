.. include:: references.rst
.. _configuration_link:

Configuration
=============

At startup, `Magpie` application will load multiple configuration files to define various behaviours or setup
operations. These are defined though the configuration settings presented in below sections.

All generic `Magpie` configuration settings can be defined through either the `magpie.ini`_ file or environment
variables. Values defined in `magpie.ini`_ are expected to follow the ``magpie.[variable_name]`` format, and
corresponding ``MAGPIE_[VARIABLE_NAME]`` format is used for environment variables. Both of these alternatives match
the constants defined in `constants.py`_ and can be used interchangeably.

.. versionchanged:: 1.1
    Order of resolution will prioritize *setting configurations* over *environment variables* in case of duplicates
    resulting into different values. Environment variables will not override already specified setting values.

    Previous versions of `Magpie` would instead prioritize environment variables, but this behaviour was deemed as
    counter intuitive. This is attributed to the global scope nature of environment variables that often made it hard
    to understand why some custom INI file would not behave as intended since those variable would inconsistently take
    precedence whether or not they were defined. Using a common configuration file makes it easier to maintain and
    understand the applied settings, and is therefore preferable.

Configuration Files
-------------------

File: magpie.ini
~~~~~~~~~~~~~~~~~~~

This is the base configuration file that defines most of `Magpie`'s lower level configuration. A basic example is
provided in `magpie.ini`_ which should allow any user to run the application locally. Furthermore, this file
is used by default in each tagged Docker image. If you want to provide different configuration, the file should be
overridden in the Docker image using a volume mount parameter, or by specifying an alternative path through the
environment variable ``MAGPIE_INI_FILE_PATH``.

File: magpie.env
~~~~~~~~~~~~~~~~~~~

By default, `Magpie` will try to load a ``magpie.env`` file which can define further environment variable definitions
used to setup the application (see ``MAGPIE_ENV_FILE`` setting further below). An example of expected format and common
variables for this file is presented in `magpie.env.example`_.

.. warning::
    If ``magpie.env`` cannot be found (e.g.: using setting ``MAGPIE_ENV_FILE``) but `magpie.env.example`_ is available
    after resolving any previously set ``MAGPIE_ENV_DIR`` variable, this example file will be used to make a copy saved
    as ``magpie.env`` and will be used as the base ``.env`` file to load its contained environment variables.
    This behaviour is intended to reduce initial configuration and preparation of  `Magpie` for a new user.

    When loading variables from the ``.env`` file, any conflicting environment variable will **NOT** be overridden.
    Therefore, only *missing but required* values will be added to the environment to ensure proper setup of `Magpie`.

File: postgres.env
~~~~~~~~~~~~~~~~~~~

This file behaves exactly in the same manner as for ``magpie.env`` above, but for specific variables definition
employed to setup the `postgres` database connection (see ``MAGPIE_POSTGRES_ENV_FILE`` setting below).
File `postgres.env.example`_ and auto-resolution of missing ``postgres.env`` is identical to ``magpie.env``
case.

File: providers.cfg
~~~~~~~~~~~~~~~~~~~

This configuration file allows automatically registering :term:`Service` definitions in `Magpie` at startup. When the
application starts, it will look for corresponding services and add them to the database as required. It will also
look for mismatches between the :term:`Service` name and URL with the corresponding entry in the database to update it
to the desired URL. See ``MAGPIE_PROVIDERS_CONFIG_PATH`` setting below to setup alternate references to this type of
configuration. Please refer to the comment header of sample file `providers.cfg`_ for specific format and parameter
details.

.. versionchanged:: 3.1
    Some services, such as :ref:`ServiceTHREDDS` for instance, can take additional parameters to customize some of
    their behaviour. Please refer to :ref:`Services` chapter for specific configuration supported.

File: permissions.cfg
~~~~~~~~~~~~~~~~~~~~~~

This configuration file allows automatically registering or cleaning :term:`Permission` definitions in `Magpie` at
startup. Each specified update operation is applied for the corresponding :term:`User` or :term:`Group` onto the
specific :term:`Service` or :term:`Resource`. This file is processed after `providers.cfg`_ in order to allow
permissions to be applied on freshly registered services. Furthermore, sub-resources are automatically created if they
can be iteratively resolved with provided parameters of the corresponding permission entry (resources should be defined
using tree-path in this case, see format in :func:`magpie.api.management.resources.resources_utils.get_resource_path`).

See ``MAGPIE_PERMISSIONS_CONFIG_PATH`` setting below to setup alternate references to this type of configuration.
Please refer to the comment header of sample file `permissions.cfg`_ for specific format details as well as specific
behaviour of each parameter according to encountered use cases.

Configuration File Formats
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionchanged:: 1.9.2

Any file represented in the :ref:`Configuration` chapter using any of the extension ``.cfg``, ``.json``, ``.yaml`` or
``.yml`` will be accepted interchangeably if provided. Both parsing as JSON and YAML will be attempted for backward
compatibility of each resolved file path.

It is not mandatory for the the name of each file to also match the employed name in the documentation, provided
the paths can be resolved to valid files, though there is special handling of default ``.example`` extensions with
matching file names when no other alternative configurations can be found. Again, this is mostly for backward
compatibility.

.. _config_file:

Combined Configuration File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 2.0

Since contents of all different configurations files (`providers.cfg`_, `permissions.cfg`_) reside under distinct
top-level objects, it is actually possible to use an unique file to define everything. For example, one could define
a combined configuration as follows.

.. code-block:: YAML

    # inside 'config.yml'

    providers:
      some-service:
        url: http://${HOSTNAME}:8000
        title: Some Service
        public: true
        c4i: false
        type: api

    groups:
      - name: my-group
        description: My Custom Group
        discoverable: false

    users:
      - username: my-user
        group: my-group  # will reference above group

    permissions:
      - service: api
        resource: /resource/user-resource  # will create both resources respecting children relationship
        type: route      # not mandatory here since service type 'api' only allows this type, but useful for other cases
        permission: read
        user: my-user    # will reference above user
        action: create
      - service: api
        resource: /groups
        permission: read
        group: my-group  # will reference above group
        action: create

    webhooks:
      create :
        - <url1>
        - <url2>
        - ...
      delete :
        - <url1>
        - <url2>
        - ...



For backward compatibility reasons, `Magpie` will first look for separate files to load each section individually.
To enforce using a combined file as above, either provide ``MAGPIE_CONFIG_PATH = <path>/config.yml`` or ensure that each
specific environment variable ``MAGPIE_PROVIDERS_CONFIG_PATH`` and ``MAGPIE_PERMISSIONS_CONFIG_PATH`` point to the same
actual file. For all of these variables, ``magpie.[variable_name]`` formatted settings are also supported through
definitions within ``magpie.ini``.

When loading configurations from a combined file, the order of resolution of each section is the same as when loading
definitions from multiple files, meaning that ``providers`` are first registered, followed by individual
``permissions``, with the dynamic creation of any missing ``user`` or ``group`` during this process. If an explicit
``user`` or ``group`` definition can be found under the relevant sections, additional parameters are employed for their
creation. Otherwise defaults are assumed and only the specified user or group name are employed. Please refer to files
`providers.cfg`_ and `permissions.cfg`_ for further details about specific formatting and behaviour of each available
field.

A section for ``webhooks`` has also been added to the combined configuration file. This section defines a list of
urls that should be called when either creating or deleting a user. The webhooks urls are responsible for any extra
steps that should be taken on external services during the user creation/deletion.

Settings and Constants
----------------------

Environment variables can be used to define all following configurations (unless mentioned otherwise with
``[constant]`` keyword next to the parameter name). Most values are parsed as plain strings, unless they refer to an
activatable setting (e.g.: ``True`` or ``False``), or when specified with more specific ``[<type>]`` notation.

Configuration variables will be used by `Magpie` on startup unless prior definition is found within `magpie.ini`_.
All variables (i.e.: non-``[constant]`` parameters) can also be specified by their ``magpie.[variable_name]`` setting
counterpart as described at the start of the `Configuration`_ section.

Loading Settings
~~~~~~~~~~~~~~~~~

These settings can be used to specify where to find other settings through custom configuration files.

- ``MAGPIE_MODULE_DIR`` [constant]

  Path to the top level `Magpie` module (ie: source code).

- ``MAGPIE_ROOT`` [constant]

  Path to the containing directory of `Magpie`. This corresponds to the directory where the repository was cloned
  or where the package was installed.

- | ``MAGPIE_CONFIG_DIR``
  | (Default: ``${MAGPIE_ROOT}/config``)

  Configuration directory where to look for ``providers.cfg`` and ``permissions.cfg`` files.

- | ``MAGPIE_PROVIDERS_CONFIG_PATH``
  | (Default: ``${MAGPIE_CONFIG_DIR}/providers.cfg``)

  Path where to find a `providers.cfg`_ file. Can also be a directory path, where all contained ``.cfg`` files will
  be considered as `providers` files and will be loaded sequentially.

  .. note::
    If a directory path is specified, the order of loaded configuration files is not guaranteed
    (depending on OS implementation). Duplicate entries could therefore be loaded in inconsistent order.
    Please refer to `providers.cfg`_ for specific format details and loading methodology according to arguments.

- | ``MAGPIE_PERMISSIONS_CONFIG_PATH``
  | (default: ``${MAGPIE_CONFIG_DIR}/permissions.cfg``)

  Path where to find `permissions.cfg`_ file. Can also be a directory path, where all contained ``.cfg`` files will
  be considered as `permissions` files and will be loaded sequentially.

  .. note::
    If a directory path is specified, the order of loaded configuration files is not guaranteed
    (depending on OS implementation). Therefore, cross-file references to services or resources should be avoided
    to ensure that, for example, any parent resource dependency won't be missing because it was specified in a second
    file loaded after the first. Corresponding references can be duplicated across files and these conflicts will be
    correctly handled according to configuration loading methodology.
    Please refer to `permissions.cfg`_ for specific format details and loading methodology according to arguments.

- ``MAGPIE_CONFIG_PATH``

  Path where to find a combined YAML configuration file which can include ``providers``, ``permissions``, ``users``
  and ``groups`` sections to sequentially process registration or removal of items at `Magpie` startup.

  .. note::
    When provided, all other combinations of ``MAGPIE_CONFIG_DIR``, ``MAGPIE_PERMISSIONS_CONFIG_PATH`` and
    ``MAGPIE_PROVIDERS_CONFIG_PATH`` are effectively ignored in favour of definitions in this file.
    See :ref:config_file` for further details and example.

- ``MAGPIE_INI_FILE_PATH``

  Specifies where to find the initialization file to run `Magpie` application.

  .. note::
    This variable ignores the setting/env-var resolution order since settings cannot be defined without
    firstly loading the file referenced by its value.

- | ``MAGPIE_ENV_DIR``
  | (Default: ``"${MAGPIE_ROOT}/env"``)

  Directory path where to look for ``.env`` files. This variable can be useful to load specific test environment
  configurations or to specify a local path while the actual `Magpie` code is located in a Python `site-packages`
  directory (``.env`` files are not installed to avoid hard-to-resolve settings loaded from an install location).

- | ``MAGPIE_ENV_FILE``
  | (Default: ``"${MAGPIE_ENV_DIR}/magpie.env"``)

  File path to ``magpie.env`` file with additional environment variables to configure the application.

- | ``MAGPIE_POSTGRES_ENV_FILE``
  | (Default: ``"${MAGPIE_ENV_DIR}/postgres.env"``)

  File path to ``postgres.env`` file with additional environment variables to configure the `postgres` connection.

Application Settings
~~~~~~~~~~~~~~~~~~~~~

Following configuration parameters are used to define values that are employed by `Magpie` after loading
the `Loading Settings`_. All ``magpie.[variable_name]`` counterpart definitions are also available as described
at the start of the `Configuration`_ section.

- | ``MAGPIE_URL``
  | (Default: ``"http://localhost:2001"``)

  Full hostname URL to use so that `Magpie` can resolve his own running instance location.

  .. note::
    If the value is not set, `Magpie` will attempt to retrieve this critical information through other variables such
    as ``MAGPIE_HOST``, ``MAGPIE_PORT``, ``MAGPIE_SCHEME`` and ``HOSTNAME``. Modifying any of these variables
    partially is permitted but will force `Magpie` to attempt building the full URL as best as possible from the
    individual parts. The result of these parts (potential using corresponding defaults) will have the following format:
    ``"${MAGPIE_SCHEME}//:${MAGPIE_HOST}:${MAGPIE_PORT}"``.

- | ``MAGPIE_SCHEME``
  | (Default: ``"http"``)

  Protocol scheme URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.

- | ``MAGPIE_HOST``
  | (Default: ``"localhost"``)

  Domain host URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.

- | ``MAGPIE_PORT`` [:class:`int`]
  | (Default: ``2001``)

  Port URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.

- | ``MAGPIE_SECRET``
  | (Default: ``2001``)

  Port URL part of `Magpie` application to rebuild the full ``MAGPIE_URL``.

- | ``MAGPIE_CRON_LOG``
  | (Default: ``"~/magpie-cron.log"``)

  Path that the ``cron`` operation should use for logging.

- | ``MAGPIE_LOG_LEVEL``
  | (Default: ``INFO``)

  Logging level of operations. `Magpie` will first use the complete logging configuration found in
  `magpie.ini`_ in order to define logging formatters and handler referencing to the ``logger_magpie`` section.
  If this configuration fail to retrieve an explicit logging level, this configuration variable is used instead to
  prepare a basic logger, after checking if a corresponding ``magpie.log_level`` setting was instead specified.

  .. warning::
    When setting ``DEBUG`` level or lower, `Magpie` will potentially dump some sensitive information in logs such
    as access tokens. It is important to avoid this setting for production systems.

- | ``MAGPIE_LOG_PRINT``
  | (Default: ``False``)

  Specifies whether `Magpie` logging should also **enforce** printing the details to the console when using
  `CLI helpers <utilities_helpers>`_.
  Otherwise, the configured logging methodology in `magpie.ini`_ is used (which can also define a console handler).

- | ``MAGPIE_LOG_REQUEST``
  | (Default: ``True``)

  Specifies whether `Magpie` should log incoming request details.

  .. note::
    This can make `Magpie` quite verbose if large quantity of requests are accomplished.

- | ``MAGPIE_LOG_EXCEPTION``
  | (Default: ``True``)

  Specifies whether `Magpie` should log a raised exception during a process execution.

- | ``MAGPIE_UI_ENABLED``
  | (Default: ``True``)

  Specifies whether `Magpie` graphical user interface should be available with the started instance. If disabled,
  all routes that normally refer to the UI will return ``404``, except the frontpage that will return a simple JSON
  description as it is normally the default entrypoint of the application.

- | ``MAGPIE_UI_THEME``
  | (Default: ``"blue"``)

  Specifies the adjustable theme to apply `Magpie` UI pages. This theme consist principally of the applied color for
  generic interface items, but could be extended at a later date. The value must be one of the CSS file names located
  within the `themes`_ subdirectory.


Security Settings
~~~~~~~~~~~~~~~~~~~~~

Following configuration parameters are used to define specific values that are related to security configurations.
Again, the `Loading Settings`_ will be processed beforehand and all ``magpie.[variable_name]`` setting definitions
remain available as described at the start of the `Configuration`_ section.

- ``MAGPIE_SECRET``
  .. no default since explicit value is now required

  Secret value employed to encrypt user authentication tokens.

  .. warning::
    Changing this value at a later time will cause previously created user tokens from passwords to be invalidated.
    This value **MUST** be defined before starting the application in order to move on to user accounts and permissions
    creation in your `Magpie` instance. The application will quit with an error if this value cannot be found.

  .. versionchanged:: 2.0
    Prior to this version, a default value was employed if this setting not provided. Later `Magpie` version now
    require an explicit definition of this parameter to avoid weak default configuration making the protected system
    prone to easier breaches. This also avoids incorrect initial setup of special :term:`User`s with that temporary
    weak secret that would need recreation to regenerate passwords.

- | ``MAGPIE_COOKIE_NAME``
  | (Default: ``"auth_tkt"``)

  Identifier of the cookie that will be used for reading and writing in the requests from login and for
  user authentication operations.

- | ``MAGPIE_COOKIE_EXPIRE`` [:class:`int`]
  | (Default: ``None``)

  Lifetime duration in seconds of the cookies. Tokens become invalid after this duration is elapsed.

  When no value is provided, the cookies will have an infinite duration (never expire).
  When a valid integer value is provided, their reissue time (how long until a new token is regenerated) is a factor
  of 10 from this expiration time. For example, tokens are reissued after 360 seconds if their expiration is 3600.

- ``MAGPIE_ADMIN_USER``
  .. no default since explicit value is now required

  Name of the default 'administrator' generated by the application.

  This :term:`User` is required for initial launch of the application to avoid being 'locked out' as routes for creating
  new users require administrative access rights. It should be used as a first login method to setup other accounts.
  It is afterwards recommended to employ other user accounts with ``MAGPIE_ADMIN_GROUP`` membership to accomplish
  administrative management operations.

  If this :term:`User` is missing, it is automatically recreated on following start. The best way to invalidate its
  credentials is therefore to completely remove its entry from the database so it gets regenerated from updated
  configuration values. Note also that modifying this value without actually updating the user entry in the database
  could cause other operations to fail drastically since this special user will be employed by other `Magpie` internal
  operations such as :ref:`Service Synchronization` and setup during the application startup.

  .. versionchanged:: 2.0
    Prior to this version, a default value was employed if this setting was not provided. Later `Magpie` version now
    require an explicit definition of this parameter to avoid weak default configuration making the protected system
    prone to easier breaches. This value **MUST** be defined before starting the application in order to resume to any
    other operation in your `Magpie` instance. The application will quit with an error if this value cannot be found.
    It is recommended that the developer configures every new instance with server-specific and strong credentials.

- ``MAGPIE_ADMIN_PASSWORD``
  .. no default since explicit value is now required

  Password of the default 'administrator' :term:`User` generated by the application (see ``MAGPIE_ADMIN_USER`` details).

  .. versionchanged:: 2.0
    Prior to this version, a default value was employed if this setting was not provided. Later `Magpie` version now
    require an explicit definition of this parameter to avoid weak default configuration making the protected system
    prone to easier breaches. This value **MUST** be defined before starting the application in order to resume to any
    other operation in your `Magpie` instance. The application will quit with an error if this value cannot be found.
    It is recommended that the developer configures every new instance with server-specific and strong credentials.

- | ``MAGPIE_ADMIN_EMAIL``
  | (Default: ``"${MAGPIE_ADMIN_USER}@mail.com"``)

  Email of the default 'administrator' generated by the application.

- | ``MAGPIE_ADMIN_GROUP``
  | (Default: ``"administrators"``)

  Name of the default 'administrator' :term:`Group` generated by the application.

  .. note::
    To simplify configuration of future administrators of the application, all their :ref:`Inherited Permissions` are
    shared through this :term:`Group` instead of setting individual permissions on each :term:`User`. It is recommended
    to keep defining such higher level permissions on this :term:`Group` to ease the management process of granted
    access to all their members, or in other words, to allow multiple administrators to manage `Magpie` resources with
    their respective accounts.

- | ``MAGPIE_ADMIN_PERMISSION`` [constant]
  | (Value: ``"admin"``)

  Name of the :term:`Permission` used to represent highest administration privilege in the application. It is one of
  the special :term:`Access Permissions` known by the application (see also :ref:`Route Access` section).

- | ``MAGPIE_LOGGED_PERMISSION`` [constant]
  | (Value: ``"MAGPIE_LOGGED_USER"``)

  .. versionadded:: 2.0

  Defines a special condition of :term:`Access Permissions` related to the :term:`Logged User` session and the
  targeted :term:`User` by the request. See details in :ref:`Route Access` for when it applies.

- | ``MAGPIE_LOGGED_USER`` [constant]
  | (Value: ``"current"``)

  Keyword used to define route resolution using the currently logged in user. This value allows, for example,
  retrieving the user details of the logged user with ``GET /users/${MAGPIE_LOGGED_USER}`` instead of having to
  find explicitly the ``GET /users/<my-user-id>`` variant. User resolution is done using the authentication cookie
  found in the request. If no cookie can be found, it defaults to the ``MAGPIE_ANONYMOUS_USER`` value.

  .. note::
    Because the :term:`Logged User` executing the request with this keyword is effectively the authenticated user,
    the behaviour of some specific paths can be slightly different than their literal ``user_name`` counterpart.
    For example, :term:`User` details will be accessible to the :term:`Logged User` (he can view his own information)
    but this same user will receive a forbidden response if using is ID in the path if he doesn't have required
    privileges.

  .. versionchanged:: 2.0
    Even without administrative access rights, the :term:`Logged User` is allowed to obtain some additional details
    about the targeted :term:`User` of the request path if it corresponds to itself. See ``MAGPIE_LOGGED_PERMISSION``
    and :ref:`Route Access` for further details.

- | ``MAGPIE_ANONYMOUS_USER``
  | (Default: ``"anonymous"``)

  Name of the default :term:`User` that represents non logged-in user (ie: invalid or no :term:`Authentication`
  token provided). This :term:`User` is used to manage :term:`Public` access to :term:`Service` and :term:`Resource`.

- | ``MAGPIE_ANONYMOUS_PASSWORD`` [constant]
  | (Default: ``${MAGPIE_ANONYMOUS_USER}``)

  Password of the default unauthenticated :term:`User`.
  This value is not modifiable directly and is available only for preparation of the default user on startup.

- | ``MAGPIE_ANONYMOUS_EMAIL``
  | Email of the default unauthenticated :term:`User`.
  | (Default: ``"${MAGPIE_ANONYMOUS_USER}@mail.com"``)

- | ``MAGPIE_ANONYMOUS_GROUP`` [constant]
  | (Default: ``${MAGPIE_ANONYMOUS_USER}``)

  Special :term:`Group` name that defines :ref:`Public Access` functionalities. All users are automatically member of
  this :term:`Public` :term:`Group` to obtain :ref:`Inherited Permissions`.

  This parameter is enforced to be equal to ``MAGPIE_ANONYMOUS_USER``. It is preserved for backward compatibility of
  migration scripts and external libraries that specifically refer to this parameter.

  .. versionchanged:: 2.0
    The :term:`Group` generated by this configuration cannot be modified to remove :term:`User` memberships or change
    other metadata associated to it.

  .. warning::
    To set :term:`Public` permissions, one should always set them on this :term:`Group` instead of directly on
    ``MAGPIE_ANONYMOUS_USER`` as setting them directly on that :term:`User` will cause unexpected behaviours.
    See :ref:`Public Access` section for full explanation.

- | ``MAGPIE_EDITOR_GROUP``
  | (Default: ``"editors"``)

  *Unused for the moment.*

- | ``MAGPIE_USERS_GROUP``
  | (Default: ``"users"``)

  Name of a generic :term:`Group` created to associate registered :term:`User` memberships in the application.

  .. versionchanged:: 2.0
    New :term:`User` are **NOT** automatically added to this :term:`Group` anymore. This :term:`Group` remains
    available for testing and backward compatibility reasons, but doesn't have any special connotation and can be
    modified just as any other normal :term:`Group`.

    Prior versions of `Magpie` were adding every new :term:`User` to that :term:`Group` which made it no different
    than the behaviour fulfilled by ``MAGPIE_ANONYMOUS_GROUP`` which they are also member of. Since
    ``MAGPIE_USERS_GROUP`` has no special meaning and is modifiable at any time (e.g.: users could be removed from it),
    it could not even be employed to ensure provision of permissions applied to all users (its original purpose), which
    is also equivalent to functionalities provided with :term:`Public` permissions inherited by
    ``MAGPIE_ANONYMOUS_GROUP`` that is more specifically handled by `Magpie` for this purpose.

- | ``MAGPIE_USER_NAME_MAX_LENGTH`` [:class:`int`]
  | (Default: ``64``)

  Maximum length to consider a :term:`User` name as valid.
  The name specified during creation will be forbidden if longer.

  .. warning::
    This value should not be greater than the token length used to identify a :term:`User` to preserve internal
    functionalities.

- | ``MAGPIE_PASSWORD_MIN_LENGTH``
  | (Default: ``12``)

  .. versionadded:: 2.0
    Minimum length of the password for :term:`User` creation or update.

  .. note::
    Because of backward-compatibility requirements, passwords are not enforced this condition during login procedure
    as shorter passwords could have been used and not yet updated for older accounts.

- | ``MAGPIE_DEFAULT_PROVIDER`` [constant]
  | (Value: ``"ziggurat"``)

  Name of the :term:`Provider` used for login. This represents the identifier that is set to define how to
  differentiate between a local sign-in procedure and a dispatched one some known `Authentication Providers`_.

Phoenix Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings provide some integration support for `Phoenix`_ in order to synchronize its service definitions with
`Magpie` services.

.. warning::
    Support of `Phoenix`_ is fairly minimal. It is preserved for historical and backward compatibility but is
    not actively tested. Please submit an `issue`_ if you use it and some unexpected behaviour is encountered.

- | ``PHOENIX_USER``
  | (Default: ``"phoenix"``)

  Name of the user to use for :term:`Authentication` in `Phoenix`_.

- | ``PHOENIX_PASSWORD``
  | (Default: ``"qwerty"``)

  Password of the user to use for :term:`Authentication` in `Phoenix`_.

- | ``PHOENIX_HOST``
  | (Default: ``${HOSTNAME}"``)

  Hostname to use for `Phoenix`_ connection to accomplish :term:`Authentication` and :ref:`Service Synchronization`.

- | ``PHOENIX_PORT`` [:class:`int`]
  | (Default: ``8443``)

  Port to use for `Phoenix`_ connection to accomplish :term:`Authentication` and :ref:`Service Synchronization`.

- | ``PHOENIX_PUSH``
  | (Default: ``True``)

  Whether to push new :ref:`Service Synchronization` settings to the referenced `Phoenix`_ connection.


Twitcher Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings define parameters required by `Twitcher`_ (OWS Security Proxy) in order to interact with
`Magpie` services.


- | ``TWITCHER_PROTECTED_PATH``
  | (Default: ``"/ows/proxy"``)

  HTTP path used to define the protected (public) base path of services registered in `Magpie` that will be served
  by an existing `Twitcher`_ proxy application after :term:`Access Control List` (ACL) verification of the
  :term:`Logged User`.

  .. note::
    Using this parameter to define `Twitcher`_'s path assumes that it resides under the same server domain as the
    `Magpie` instance being configured (ie: hostname is inferred from resolved value amongst ``MAGPIE_URL``,
    ``MAGPIE_HOST``, ``TWITCHER_HOST`` and ``HOSTNAME`` settings or environment variables).

  .. warning::
    Path is intended to be employed with `Twitcher`_ residing side-by-side with `Magpie`. Therefore, prefix
    ``/twitcher`` is added unless already explicitly provided. To employ another path without prefix, consider
    instead providing it with the full URL using ``TWITCHER_PROTECTED_URL`` parameter.

- | ``TWITCHER_HOST``
  | (Default: None)

  .. versionadded:: 2.0

  Specifies the explicit hostname to employ in combination with ``TWITCHER_PROTECTED_PATH`` to form the complete base
  service protected URL. Ignored if ``TWITCHER_PROTECTED_URL`` was provided directly. If not provided, hostname
  resolution falls back to using ``HOSTNAME`` environment variable.

  .. note::
    The resulting URL will take the form ``https://{TWITCHER_HOST}[/twitcher]{TWITCHER_PROTECTED_PATH}`` to imitate
    the resolution of ``TWITCHER_PROTECTED_URL`` considering provided ``TWITCHER_PROTECTED_PATH``.

- | ``TWITCHER_PROTECTED_URL``
  | (Default: *see note*)

  Defines the protected (public) full base URL of services registered in `Magpie`. This setting is mainly to allow
  specifying an alternative domain where a remote `Twitcher`_ instance could reside.

  .. note::
    When not provided, attempts to infer the value by combining the environment variable ``HOSTNAME`` or
    ``TWITCHER_HOSTNAME``, and an optional ``/twitcher`` prefix (as needed to match incoming request) and the
    value provided by ``TWITCHER_PROTECTED_PATH``.


Please note that although `Twitcher`_ URL references are needed to configure interactive parameters with `Magpie`, the
employed `Twitcher`_ instance will also need to have access to `Magpie`'s database in order to allow proper
:term:`Service` resolution with `magpie.adapter.magpieservice.MagpieServiceStore`. Appropriate database credentials
must therefore be shared between the two services, as well as ``MAGPIE_SECRET`` value in order for successful
completion of the handshake during :term:`Authentication` procedure of the request :term:`User` token.


Postgres Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings define parameters required to define the `PostgreSQL`_ database connection employed by `Magpie` as
well as some other database-related operation settings. Settings defined by ``magpie.[variable_name]`` definitions
are available as described at the start of the `Configuration`_ section, as well as some special cases where additional
configuration names are supported where mentioned.

- | ``MAGPIE_DB_MIGRATION``
  | (Default: ``True``)

  Run database migration on startup in order to bring it up to date using `Alembic`_.

- | ``MAGPIE_DB_MIGRATION_ATTEMPTS``
  | (Default: ``5``)

  Number of attempts to re-run database migration on startup in case it failed (eg: due to connection error).

- | ``MAGPIE_DB_URL``
  | (Default: *see note*)

  Full database connection URL formatted as ``<db-type>://<user>:<password>@<host>:<port>/<db-name>``.

  Please refer to `SQLAlchemy Engine`_'s documentation for supported database implementations and their corresponding
  configuration.

  .. warning::
    Only `PostgreSQL`_ has been extensively tested with `Magpie`, but other variants *could* be applicable.

  .. note::
    By default, ``postgresql`` database connection URL is inferred by combining al below ``MAGPIE_POSTGRES_<>``
    parameters if the value was not explicitly provided.

- | ``MAGPIE_POSTGRES_USERNAME``
  | (Default: ``"magpie"``)

  Database connection username to retrieve `Magpie` data stored in `PostgreSQL`_.

  .. versionchanged:: 1.9
      On top of ``MAGPIE_POSTGRES_USERNAME``, environment variable ``POSTGRES_USERNAME`` and setting
      ``postgres.username`` are all supported interchangeably. For backward compatibility, all above variants with
      ``user`` instead of ``username`` (with corresponding lower/upper case) are also verified for potential
      configuration if no prior parameter was matched. The lookup order of each name variant is as they were presented,
      while also keeping the setting name priority over an equivalent environment variable name.

- | ``MAGPIE_POSTGRES_PASSWORD``
  | (Default: ``"qwerty"``)

  Database connection password to retrieve `Magpie` data stored in `PostgreSQL`_.

  .. versionchanged:: 1.9
    Environment variable ``POSTGRES_PASSWORD`` and setting ``postgres.password`` are also supported if not previously
    identified by their `Magpie`-prefixed variants.

- | ``MAGPIE_POSTGRES_HOST``
  | (Default: ``"postgres"``)

  Database connection host location to retrieve `Magpie` data stored in `PostgreSQL`_.

  .. versionchanged:: 1.9
    Environment variable ``POSTGRES_HOST`` and setting ``postgres.host`` are also supported if not previously
    identified by their `Magpie`-prefixed variants.

- | ``MAGPIE_POSTGRES_PORT`` [:class:`int`]
  | (Default: ``5432``)

  Database connection port to retrieve `Magpie` data stored in `PostgreSQL`_.

  .. versionchanged:: 1.9
    Environment variable ``POSTGRES_PORT`` and setting ``postgres.port`` are also supported if not previously
    identified by their `Magpie`-prefixed variants.

- | ``MAGPIE_POSTGRES_DB``
  | (Default: ``"magpie"``)

  Name of the database located at the specified connection to retrieve `Magpie` data stored in `PostgreSQL`_.

  .. versionchanged:: 1.9
    Environment variable ``POSTGRES_DB`` and setting ``postgres.db``, as well as the same variants with ``database``
    instead of ``db``, are also supported if not previously identified by their `Magpie`-prefixed variants.

.. _SQLAlchemy Engine: https://docs.sqlalchemy.org/en/13/core/engines.html


Authentication Providers
---------------------------

In order to perform :term:`Authentication` in `Magpie`, multiple :term:`Providers` are supported. By default,
the :term:`Internal Provider` named ``ziggurat``, which corresponds to the package used to manage all `Magpie` elements
internally, is employed. Supported :term:`External Providers` are presented in the table below, although more could be
added later on. To signin using one of these :term:`Providers`, the corresponding identifier must be provided within
the signin request contents.

Each as different configuration parameters as defined in `MagpieSecurity`_ and use various protocols amongst
``OpenID``, ``ESGF``-flavored ``OpenID`` and ``OAuth2``. Further :term:`External Providers` can be defined using this
module's dictionary configuration style following parameter specification of `Authomatic`_ package used for managing
this :term:`Authentication` procedure.

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

.. note::
    Please note that due to the constantly changing nature of multiple of these external providers (APIs and moved
    Websites), rarely used authentication bridges by the developers could break without prior notice. If this is the
    case and you use one of the broken connectors, summit a new `issue`_.


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
