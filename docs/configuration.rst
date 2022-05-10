.. include:: references.rst
.. _configuration:

Configuration
=============

At startup, `Magpie` application will load multiple configuration files to define various behaviours or setup
operations. These are defined through the configuration settings presented in below sections.

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

.. _config_magpie_ini:

File: magpie.ini
~~~~~~~~~~~~~~~~~~~

This is the base configuration file that defines most of `Magpie`'s lower level configuration. A basic example is
provided in `magpie.ini`_ which should allow any user to run the application locally. Furthermore, this file
is used by default in each tagged Docker image. If you want to provide different configuration, the file should be
overridden in the Docker image using a volume mount parameter, or by specifying an alternative path through the
environment variable :envvar:`MAGPIE_INI_FILE_PATH`.

.. _config_magpie_env:

File: magpie.env
~~~~~~~~~~~~~~~~~~~

By default, `Magpie` will try to load a ``magpie.env`` file which can define further environment variable definitions
used to setup the application (see :envvar:`MAGPIE_ENV_FILE` setting further below). An example of expected format and
common variables for this file is presented in `magpie.env.example`_.

.. warning::
    If ``magpie.env`` cannot be found (e.g.: using setting :envvar:`MAGPIE_ENV_FILE`) but `magpie.env.example`_ is
    available after resolving any previously set :envvar:`MAGPIE_ENV_DIR` variable, this example file will be used to
    make a copy saved as ``magpie.env`` and will be used as the base ``.env`` file to load its contained environment
    variables. This behaviour is intended to reduce initial configuration and preparation of  `Magpie` for a new user.

    When loading variables from the ``.env`` file, any conflicting environment variable will **NOT** be overridden.
    Therefore, only *missing but required* values will be added to the environment to ensure proper setup of `Magpie`.

.. _config_postgres_env:

File: postgres.env
~~~~~~~~~~~~~~~~~~~

This file behaves exactly in the same manner as for ``magpie.env`` above, but for specific variables definition
employed to setup the `PostgreSQL`_ database connection (see :envvar:`MAGPIE_POSTGRES_ENV_FILE` setting below).
File `postgres.env.example`_ and auto-resolution of missing ``postgres.env`` is identical to ``magpie.env``
case.

.. _config_providers:

File: providers.cfg
~~~~~~~~~~~~~~~~~~~

This configuration file allows automatically registering :term:`Service` definitions in `Magpie` at startup. When the
application starts, it will look for corresponding services and add them to the database as required. It will also
look for mismatches between the :term:`Service` name and URL with the corresponding entry in the database to update it
to the desired URL. See :envvar:`MAGPIE_PROVIDERS_CONFIG_PATH` setting below to setup alternate references to this type
of configuration. Please refer to the comment header of sample file `providers.cfg`_ for specific format and parameter
details.

.. versionchanged:: 3.1
    Some services, such as :ref:`ServiceTHREDDS` for instance, can take additional parameters to customize some of
    their behaviour. Please refer to :ref:`Services` chapter for specific configuration supported.

.. _config_permissions:

File: permissions.cfg
~~~~~~~~~~~~~~~~~~~~~~

This configuration file allows automatically registering or cleaning :term:`Permission` definitions in `Magpie` at
startup. Each specified update operation is applied for the corresponding :term:`User` and/or :term:`Group` onto the
specific :term:`Service` or :term:`Resource`. This file is processed after `providers.cfg`_ in order to allow
permissions to be applied on freshly registered services. Furthermore, sub-resources are automatically created if they
can be iteratively resolved with provided parameters of the corresponding permission entry. Resources should be defined
using tree-path in this case, as described by format in
:func:`magpie.api.management.resources.resources_utils.get_resource_path` or in example `permissions.cfg`_.

See :envvar:`MAGPIE_PERMISSIONS_CONFIG_PATH` setting below to setup alternate references to this type of configuration.
Please refer to the comment header of sample file `permissions.cfg`_ for specific format details as well as specific
behaviour of each parameter according to encountered use cases.

.. _config_formats:

Configuration File Formats
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionchanged:: 1.9.2

Any file represented in the :ref:`Configuration` chapter using any of the extension ``.cfg``, ``.json``, ``.yaml`` or
``.yml`` will be accepted interchangeably if provided. Both parsing as JSON and YAML will be attempted for backward
compatibility of each resolved file path.

It is not mandatory for the name of each file to also match the employed name in the documentation, provided
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
      - name: <webhook_name>
        action: <webhook_action>
        method: GET | HEAD | POST | PUT | PATCH | DELETE
        url: <location>
        payload:
          <param_raw>: "value"              # some literal value that will be added to the payload as is
          <param_subst>: "{<param_value>}"  # <param_value> will be substituted (must be available for that action)
          ...


For backward compatibility reasons, `Magpie` will first look for separate files to load each section individually.
To enforce using a combined file as above *instead of the separate files*, either provide
``MAGPIE_CONFIG_PATH = <path>/config.yml``, or ensure that both environment variable
:envvar:`MAGPIE_PROVIDERS_CONFIG_PATH` and :envvar:`MAGPIE_PERMISSIONS_CONFIG_PATH` specifically
refer to this same YAML file. For all of these variables, ``magpie.[variable_name]`` formatted settings are also
supported through definitions within ``magpie.ini``.

When loading configurations from a combined file, the order of resolution of each section is the same as when loading
definitions from multiple files, meaning that ``providers`` are first registered, followed by individual
``permissions``, with the dynamic creation of any missing ``user`` or ``group`` during this process. If an explicit
``user`` or ``group`` definition can be found under the relevant sections, additional parameters are employed for their
creation. Otherwise defaults are assumed and only the specified user or group name are employed. Please refer to files
`providers.cfg`_ and `permissions.cfg`_ for further details about specific formatting and behaviour of each available
field.

.. versionadded:: 3.6
    The ``webhook`` section allows to define external connectors to which `Magpie` should send requests following
    certain events. These are described in further details in :ref:`config_webhook` section.

.. versionadded:: 3.12
    Variable :envvar:`MAGPIE_WEBHOOKS_CONFIG_PATH` was added and will act in a similar fashion as their providers and
    permissions counterparts, to load definitions from multiple configuration files.

.. _config_service_hooks:

Service Hooks
~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 3.25

Under each :term:`Service` within `providers.cfg`_ or the :ref:`config_file`, it is possible to provide a section
named``hooks`` that lists additional pre/post request/response processing operations to apply when matched against
the given request filter conditions. These hooks are plugin-based Python scripts that can modify the proxied request
and responses when `Magpie` and `Twitcher`_ work together using the :ref:`utilities_adapter<Magpie Adapter>`.
Each hook must be configured using the following parameters.


.. list-table::
    :header-rows: 1
    :stub-columns: 1
    :widths: 10,10,80

    * - Field
      - Requirement
      - Description
    * - ``type``
      - **required**
      - Literal string ``{ request | response }`` of the desired instance where to invoke the hook.
    * - ``path``
      - **required**
      - :term:`Service`-specific request path or regular expression pattern to be matched for invoking the hook.
        Path starts after `Twitcher`_ proxy prefix path and :term:`Service` name (i.e.: path as if there was no proxy).
    * - ``method``
      - *optional*
      - Literal string ``{ HEAD | GET | POST | PUT | PATCH | DELETE | * }`` (default: ``*`` representing any method).
        HTTP method that must be matched for invoking the hook.
    * - ``query``
      - *optional*
      - Request query string or regular expression pattern to be matched for invoking the hook (default: ``.*``).
        Matches anything if not specified. To match explicitly no-query condition, provide an empty string (``""``).
    * - ``target``
      - **required**
      - Location of the function that will handle hook processing when request matching conditions are met.
        Path should be absolute or relative to :envvar:`MAGPIE_ROOT` and must be a valid Python file.
        Path should include the function name using format: ``some/path/script.py:func``.

More specifically, when a :term:`Service` or children :term:`Resource` is accessed, triggering a proxied request
through `Twitcher`_, the authenticated and authorized request goes through ``hooks`` processing chain that can adjust
certain request and response parameters (e.g.: add headers, filter the body, etc.), or even substitute the request
definition entirely based on ``target`` implementations. Hooks are applied in the same order as they are defined in
the configuration when they match the inbound request, propagating the request/response across each call.
Plugin scripts can therefore apply some advanced logic to improve the synergy between the protected services.
They can also be employed to apply some :term:`Service` specific operations such as filtering protected contents
that `Magpie` and `Twitcher`_ cannot themselves process evidently.

Permitted signatures of hook functions are as presented below.
The first argument (``request`` or ``response`` accordingly) is always required. Its modified definition must be
returned as well. The other parameters (``service``, ``hook``) are optional. They represent the specific configurations
that triggered the ``target`` call. Optional arguments can be specified in any order or combination, but **MUST** use
the exact argument names indicated below.

.. code-block:: python

    def request_hook(request: pyramid.request.Request) -> pyramid.request.Request: ...

    def request_hook(request: pyramid.request.Request,
                     service: magpie.typedefs.ServiceConfigItem,
                     hook: magpie.typedefs.ServiceHookConfigItem) -> pyramid.request.Request: ...

    def response_hook(response: pyramid.response.Response) -> pyramid.response.Response: ...

    def response_hook(response: pyramid.response.Response,
                      service: magpie.typedefs.ServiceConfigItem,
                      hook: magpie.typedefs.ServiceHookConfigItem) -> pyramid.response.Response: ...

.. seealso::
    File `providers.cfg`_ presents contextual information and location of the ``hooks`` schema under
    example provider definitions.

    File |test-hooks|_ presents some examples of hook ``target`` functions with common operations to
    update request and response parameters.

.. |test-hooks| replace:: tests/hooks/request_hooks.py
.. _test-hooks: https://github.com/Ouranosinc/Magpie/blob/master/tests/hooks/request_hooks.py

.. _config_constants:

Settings and Constants
----------------------

.. _constant:
.. |constant| replace:: ``constant``

Environment variables can be used to define all following configurations (unless mentioned otherwise with
[|constant|_] keyword). Most values are parsed as plain strings, unless they refer to an
activatable setting (e.g.: ``True`` or ``False``), or when specified with more specific ``[<type>]`` notation.

Configuration variables will be used by `Magpie` on startup unless prior definition is found within `magpie.ini`_.
All variables (i.e.: non-|constant|_ parameters) can also be specified by their ``magpie.[variable_name]`` setting
counterpart as described at the start of the :ref:`configuration` section.

.. _config_load_settings:

Loading Settings
~~~~~~~~~~~~~~~~~

These settings can be used to specify where to find other settings through custom configuration files.

.. envvar:: MAGPIE_MODULE_DIR

    [|constant|_]

    Path to the top level :mod:`magpie` module (i.e.: source code).

.. envvar:: MAGPIE_ROOT

    [|constant|_]

    Path to the containing directory of `Magpie`. This corresponds to the directory where the repository was cloned
    or where the package was installed.

.. envvar:: MAGPIE_CONFIG_DIR

    (Default: ``${MAGPIE_ROOT}/config``)

    Configuration directory where to look for ``providers.cfg`` and ``permissions.cfg`` files.

    If more than one file for any of those individual type of configuration needs to be loaded from a directory, the
    :envvar:`MAGPIE_PROVIDERS_CONFIG_PATH` and :envvar:`MAGPIE_PERMISSIONS_CONFIG_PATH` must be employed instead.
    Setting this variable will only look for files named *exactly* as above, unless the more explicit definitions
    of ``MAGPIE_<type>_CONFIG_PATH`` variables are also provided.

    .. warning::
        This setting is ignored if :envvar:`MAGPIE_CONFIG_PATH` is specified.

.. envvar:: MAGPIE_PROVIDERS_CONFIG_PATH

    (Default: ``${MAGPIE_CONFIG_DIR}/providers.cfg``)

    Path where to find a `providers.cfg`_ file. Can also be a directory path, where all contained configuration files
    will be parsed for ``providers`` section and will be loaded sequentially.

    Please refer to `providers.cfg`_ for specific format details and parameters.

    .. note::
        If a directory path is specified, the order of loaded configuration files is alphabetical.
        Matching :term:`Service` will be overridden by files loaded last.

    .. versionchanged:: 1.7.4

        Loading order of multiple files was **NOT** guaranteed prior to this version.

        This could lead to some entries to be loaded in inconsistent order.

    .. warning::
        This setting is ignored if :envvar:`MAGPIE_CONFIG_PATH` is specified.

.. envvar:: MAGPIE_PERMISSIONS_CONFIG_PATH

    (Default: ``${MAGPIE_CONFIG_DIR}/permissions.cfg``)

    Path where to find `permissions.cfg`_ file. Can also be a directory path, where all contained configuration files
    will be parsed for ``permissions`` section and will be loaded sequentially.

    Please refer to `permissions.cfg`_ for specific format details of the various parameters.

    .. note::
        If a directory path is specified, the order of loaded configuration files is alphabetical.

    .. versionchanged:: 1.7.4

        Loading order of multiple files was **NOT** guaranteed prior to this version.

        With older versions, cross-file references to services or resources should be avoided to ensure that,
        for example, any parent resource dependency won't be missing because it was specified in a
        second file loaded after the first. Corresponding references can be duplicated across files
        and these conflicts will be correctly handled according to configuration loading methodology.
        Later versions are safe to assume alphabetical loading order.

    .. warning::
        This setting is ignored if :envvar:`MAGPIE_CONFIG_PATH` is specified.

.. envvar:: MAGPIE_WEBHOOKS_CONFIG_PATH

    (Default: ``None``)

    .. versionadded:: 3.12

    Path where to find a file or a directory of multiple configuration files where ``webhooks`` section(s) that
    provide definitions for :ref:`config_webhook` can be loaded from.

    Examples of such configuration section is presented in the example :ref:`config_file`.
    When multiple files are available from a directory path, they are loaded by name alphabetically.

    .. warning::
        This setting is ignored if :envvar:`MAGPIE_CONFIG_PATH` is specified.

.. envvar:: MAGPIE_CONFIG_PATH

    Path where to find a combined YAML configuration file which can include ``providers``, ``permissions``, ``users``
    and ``groups`` sections to sequentially process registration or removal of items at `Magpie` startup.

    See :ref:`config_file` for further details and an example of its structure.

    .. versionchanged:: 3.6
        The configuration can also contain a ``webhooks`` section, as described in :ref:`config_webhook` and
        presented in the sample :ref:`config_file`.

    .. warning::
        When this setting is defined, all other combinations of :envvar:`MAGPIE_CONFIG_DIR`,
        :envvar:`MAGPIE_PERMISSIONS_CONFIG_PATH`, :envvar:`MAGPIE_PROVIDERS_CONFIG_PATH` and
        :envvar:`MAGPIE_WEBHOOKS_CONFIG_PATH` are effectively ignored in favour of definitions in this file.
        It is not possible to employ the single :ref:`config_file` at the same time as multi-configuration file
        loading strategy from a directory.

.. envvar:: MAGPIE_INI_FILE_PATH

    Specifies where to find the initialization file to run `Magpie` application.

    .. note::
        This variable ignores the setting/env-var resolution order since settings cannot be defined without
        firstly loading the file referenced by its value.

    .. seealso::
        `config_magpie_ini`_

.. envvar:: MAGPIE_ENV_DIR

    (Default: ``"${MAGPIE_ROOT}/env"``)

    Directory path where to look for ``.env`` files. This variable can be useful to load specific test environment
    configurations or to specify a local path while the actual `Magpie` code is located in a Python `site-packages`
    directory (``.env`` files are not installed to avoid hard-to-resolve settings loaded from an install location).

.. envvar:: MAGPIE_ENV_FILE

    (Default: ``"${MAGPIE_ENV_DIR}/magpie.env"``)

    File path to ``magpie.env`` file with additional environment variables to configure the application.

    .. seealso::
        :ref:`config_magpie_env`

.. envvar:: MAGPIE_POSTGRES_ENV_FILE

    (Default: ``"${MAGPIE_ENV_DIR}/postgres.env"``)

    File path to ``postgres.env`` file with additional environment variables to configure the `postgres` connection.

    .. seealso::
        :ref:`config_postgres_env`


.. _config_app_settings:

Application Settings
~~~~~~~~~~~~~~~~~~~~~

Following configuration parameters are used to define values that are employed by `Magpie` after loading
the `Loading Settings`_. All ``magpie.[variable_name]`` counterpart definitions are also available as described
at the start of the :ref:`Configuration` section.

.. envvar:: MAGPIE_URL

    (Default: ``"http://localhost:2001"``)

    Full hostname URL to use so that `Magpie` can resolve his own running instance location.

    .. note::
        If the value is not set, `Magpie` will attempt to retrieve this critical information through other variables
        such as :envvar:`MAGPIE_HOST`, :envvar:`MAGPIE_PORT`, :envvar:`MAGPIE_SCHEME` and :envvar:`HOSTNAME`. Modifying
        any of these variables partially is permitted but will force `Magpie` to attempt building the full URL as best
        as possible from the individual parts. The result of these parts (potential using corresponding defaults) will
        have the following format: ``"${MAGPIE_SCHEME}//:${MAGPIE_HOST}:${MAGPIE_PORT}"``.

    .. note::
        The definition of :envvar:`MAGPIE_URL` or any of its parts to reconstruct it must not be confused with
        parameters defined in the ``[server:main]`` section of the provided `magpie.ini`_ configuration. The purpose
        of variable :envvar:`MAGPIE_URL` is to define where the *exposed* application is located, often representing
        the server endpoint for which the `Magpie` instance is employed. The values of ``host`` and ``port``, or
        ``bind`` defined in ``[server:main]`` instead correspond to how the WSGI application is exposed (e.g.: through
        `Gunicorn`_), and so represents a *local* web application that must be mapped one way or another to the server
        when running within the :ref:`usage_docker`.

.. envvar:: MAGPIE_SCHEME

    (Default: ``"http"``)

    Protocol scheme URL part of `Magpie` application to rebuild the full :envvar:`MAGPIE_URL`.

.. envvar:: MAGPIE_HOST

    (Default: ``"localhost"``)

    Domain host URL part of `Magpie` application to rebuild the full :envvar:`MAGPIE_URL`.

.. envvar:: MAGPIE_PORT

    [:class:`int`]
    (Default: ``2001``)

    Port URL part of `Magpie` application to rebuild the full :envvar:`MAGPIE_URL`.

.. envvar:: MAGPIE_CRON_LOG

    (Default: ``"~/magpie-cron.log"``)

    Path that the ``cron`` operation should use for logging.

.. envvar:: MAGPIE_LOG_LEVEL

    (Default: ``INFO``)

    Logging level of operations. `Magpie` will first use the complete logging configuration found in
    `magpie.ini`_ in order to define logging formatters and handler referencing to the ``logger_magpie`` section.
    If this configuration fail to retrieve an explicit logging level, this configuration variable is used instead to
    prepare a basic logger, after checking if a corresponding ``magpie.log_level`` setting was instead specified.

    .. warning::
        When setting ``DEBUG`` level or lower, `Magpie` will potentially dump some sensitive information in logs such
        as access tokens. It is important to avoid this setting for production systems.

.. envvar:: MAGPIE_LOG_PRINT

    [:class:`bool`]
    (Default: ``False``)

    Specifies whether `Magpie` logging should also **enforce** printing the details to the console when using
    :ref:`cli_helpers`.
    Otherwise, the configured logging methodology in `magpie.ini`_ is used (which can also define a console handler).

.. envvar:: MAGPIE_LOG_REQUEST

    [:class:`bool`]
    (Default: ``True``)

    Specifies whether `Magpie` should log incoming request details.

    .. note::
        This can make `Magpie` quite verbose if large quantity of requests are accomplished.

.. envvar:: MAGPIE_LOG_EXCEPTION

    [:class:`bool`]
    (Default: ``True``)

    Specifies whether `Magpie` should log a raised exception during a process execution.

.. envvar:: MAGPIE_SMTP_USER

    (Default: ``"Magpie"``)

    .. versionadded:: 3.13

    Display name employed as sending user of notification emails.

    If explicitly overridden by an empty string, the :envvar:`MAGPIE_SMTP_FROM` is used as replacement.

.. envvar:: MAGPIE_SMTP_FROM

    (Default: ``None``)

    .. versionadded:: 3.13

    Email that identifies the sender of notification emails by the application.

    This value is also employed to run the authentication step to the SMTP server in combination with
    :envvar:`MAGPIE_SMTP_PASSWORD` if it is also provided. Furthermore, if the value is provided while
    :envvar:`MAGPIE_SMTP_USER` is empty, the default email sender (display name) will revert to this value.

.. envvar:: MAGPIE_SMTP_PASSWORD

    (Default: ``None``)

    .. versionadded:: 3.13

    Authentication password to use in combination with :envvar:`MAGPIE_SMTP_FROM` to connect the server
    specified by :envvar:`MAGPIE_SMTP_HOST` as required.

    Leave blank if SMTP server does not require or should not execute authentication step.

.. envvar:: MAGPIE_SMTP_HOST

    .. versionadded:: 3.13

    Host of the SMTP server to employ for sending notification emails.

.. envvar:: MAGPIE_SMTP_PORT

    [:class:`int`]
    (Default: ``465``)

    .. versionadded:: 3.13

    Port of the outgoing notification emails from the SMTP server.

    In case of doubt, port value ``25`` (an sometimes ``587``) is employed for non-encrypted emails.
    For secure TLS, ``587`` is the usual choice, and ``465`` when using SSL.
    Other ports based on the functionalities offered by targeted :envvar:`MAGPIE_SMTP_HOST` could be available.

    Note that :envvar:`MAGPIE_SMTP_SSL` should be set accordingly when using those standard values.
    It is strongly recommended to employ an encrypted email since transferred details by `Magpie` can potentially
    contain some sensible details.

.. envvar:: MAGPIE_SMTP_SSL

    [:class:`bool`]
    (Default: ``True``)

    .. versionadded:: 3.13

    Specifies if SSL should be employed for sending email.

    If not enabled, `Magpie` will first attempt to establish a TLS connection if the targeted SMTP server
    supports it to use encrypted emails. If it is not supported by that server, it falls back to unencrypted
    emails since no other alternatives exist.

.. envvar:: MAGPIE_TOKEN_EXPIRE

    [:class:`int`]
    (Default: ``86400`` seconds)

    .. versionadded:: 3.7

    Duration for which temporary URL tokens will remain valid until automatically removed.

    These tokens can be used for many different applications within `Magpie`, but are notably employed for handling
    callback URL operations in tandem with a given :term:`Webhook` (see also: :ref:`config_webhook_actions`).

.. envvar:: MAGPIE_UI_ENABLED

    [:class:`bool`]
    (Default: ``True``)

    Specifies whether `Magpie` graphical user interface should be available with the started instance. If disabled,
    all routes that normally refer to the UI will return ``404``, except the frontpage that will return a simple JSON
    description as it is normally the default entrypoint of the application.

.. envvar:: MAGPIE_UI_THEME

    (Default: ``"blue"``)

    Specifies the adjustable theme to apply `Magpie` UI pages. This theme consist principally of the applied color for
    generic interface items, but could be extended at a later date. The value must be one of the CSS file names located
    within the `themes`_ subdirectory.


.. _config_security:

Security Settings
~~~~~~~~~~~~~~~~~~~~~

Following configuration parameters are used to define specific values that are related to security configurations.
Again, the `Loading Settings`_ will be processed beforehand and all ``magpie.[variable_name]`` setting definitions
remain available as described at the start of the :ref:`Configuration` section.

.. envvar:: MAGPIE_SECRET

    .. no default since explicit value is now required

    Secret value employed to encrypt user authentication tokens.

    .. warning::
        Changing this value at a later time will cause previously created user tokens from passwords to be invalidated.
        This value **MUST** be defined before starting the application in order to move on to user accounts and
        permissions creation in your `Magpie` instance. The application will quit with an error if this value cannot
        be found.

    .. versionchanged:: 2.0
        Prior to this version, a default value was employed if this setting not provided. Later `Magpie` version now
        require an explicit definition of this parameter to avoid weak default configuration making the protected system
        prone to easier breaches. This also avoids incorrect initial setup of special :term:`User`s with that temporary
        weak secret that would need recreation to regenerate passwords.

.. envvar:: MAGPIE_COOKIE_NAME

    (Default: ``"auth_tkt"``)

    Identifier of the cookie that will be used for reading and writing in the requests from login and for
    :term:`User` authentication operations.

    .. seealso::
        :ref:`auth_methods`

.. envvar:: MAGPIE_COOKIE_EXPIRE

    [:class:`int`]
    (Default: ``None``)

    Lifetime duration in seconds of the cookies. Tokens become invalid after this duration is elapsed.

    When no value is provided, the cookies will have an infinite duration (never expire).
    When a valid integer value is provided, their reissue time (how long until a new token is regenerated) is a factor
    of 10 from this expiration time. For example, tokens are reissued after 360 seconds if their expiration is 3600.

.. envvar:: MAGPIE_ADMIN_USER

    .. no default since explicit value is now required

    Name of the default 'administrator' generated by the application.

    .. seealso::
        :envvar:`MAGPIE_ADMIN_PASSWORD`

    This :term:`User` is required for initial launch of the application to avoid being 'locked out' as routes for
    creating new users require administrative access rights. It should be used as a first login method to setup other
    accounts. It is afterwards recommended to employ other user accounts with :envvar:`MAGPIE_ADMIN_GROUP` membership
    to accomplish administrative management operations.

    If this :term:`User` is missing, it is automatically recreated on following application start. The best way to
    invalidate its credentials is therefore to completely remove its entry from the database so it gets regenerated
    from updated configuration values. Note also that modifying the value in the configuration without restarting the
    application so that the administrator user entry in the database can also be updated could cause other operations
    to fail drastically since this special user would be output of sync when employed by other `Magpie` operations such
    as :ref:`Service Synchronization` and :term:`Permission` setup during the application startup.

    .. versionchanged:: 2.0
        Prior to this version, a default value was employed if this setting was not provided. Later `Magpie` version
        now require an explicit definition of this parameter to avoid weak default configuration making the protected
        system prone to easier breaches. This value **MUST** be defined before starting the application in order to
        resume to any other operation in your `Magpie` instance. The application will quit with an error if this value
        cannot be found. It is recommended that the developer configures every new instance with server-specific and
        strong credentials.

        Prior versions also allowed modification of this value from the API and UI, which increased chances of having
        out-of-sync definitions between the database and :term:`Configuration` files. This is not permitted anymore.
        Changing this value should be accomplished by updating the :term:`Configuration` file and restarting the
        :ref:`usage_webapp` or calling the :ref:`cli_helpers` to register changes.

.. envvar:: MAGPIE_ADMIN_PASSWORD

    .. no default since explicit value is now required

    Password of the default *administrator* :term:`User` generated by the application.

    .. seealso::
        :envvar:`MAGPIE_ADMIN_USER`

    .. versionchanged:: 2.0
        Default values definition and update during runtime for this parameter was modified to avoid problematic
        configuration synchronization problems. See corresponding change details in above :envvar:`MAGPIE_ADMIN_USER`.

    .. versionchanged:: 3.8
        Prior to this version, changing only the :envvar:`MAGPIE_ADMIN_PASSWORD` without modification of
        :envvar:`MAGPIE_ADMIN_USER` was not handled. Following versions applies any password modification on restart
        to update credentials.

    .. warning::
        Note that if the password is modified in later versions, its new value will require to fulfill validation
        against standard password format requirements, such as :envvar:`MAGPIE_PASSWORD_MIN_LENGTH`. Older passwords
        will remain effective only if left untouched for backward compatibility, but will be flagged as potential
        security risk.

.. envvar:: MAGPIE_ADMIN_EMAIL

    (Default: ``"${MAGPIE_ADMIN_USER}@mail.com"``)

    Email of the default *administrator* generated by the application.

.. envvar:: MAGPIE_ADMIN_GROUP

    (Default: ``"administrators"``)

    Name of the default *administrator* :term:`Group` generated by the application.

    .. note::
        To simplify configuration of future administrators of the application, all their :ref:`Inherited Permissions`
        are shared through this :term:`Group` instead of setting individual permissions on each :term:`User`. It is
        recommended to keep defining such higher level permissions on this :term:`Group` to ease the management process
        of granted access to all their members, or in other words, to allow multiple administrators to manage `Magpie`
        resources with their respective accounts.

.. envvar:: MAGPIE_ADMIN_PERMISSION

    [|constant|_]
    (Value: ``"admin"``)

    Name of the :term:`Permission` used to represent highest administration privilege in the application. It is one of
    the special :term:`Access Permission` known by the application (see also :ref:`Route Access` section).

.. envvar:: MAGPIE_LOGGED_PERMISSION

    [|constant|_]
    (Value: ``"MAGPIE_LOGGED_USER"``)

    .. versionadded:: 2.0

    Defines a special condition of :term:`Access Permission` related to the :term:`Logged User` session and the
    targeted :term:`User` by the request. See details in :ref:`Route Access` for when it applies.

.. envvar:: MAGPIE_LOGGED_USER

    [|constant|_]
    (Value: ``"current"``)

    Keyword used to define route resolution using the currently :term:`Logged User`. This value allows, for example,
    retrieving the user details of the logged user with ``GET /users/${MAGPIE_LOGGED_USER}`` instead of having to
    find explicitly the ``GET /users/<my-user-id>`` variant. User resolution is done using the authentication cookie
    found in the request. If no cookie can be found, it defaults to the :envvar:`MAGPIE_ANONYMOUS_USER` value.

    .. note::
        Because the :term:`Logged User` executing the request with this keyword is effectively the authenticated user,
        the behaviour of some specific paths can be slightly different than their literal ``user_name`` counterpart.
        For example, :term:`User` details will be accessible to the :term:`Logged User` (he can view his own
        information) but this same user will receive a forbidden response if using is ID in the path if he doesn't
        have required privileges.

    .. versionchanged:: 2.0
        Even without administrative access rights, the :term:`Logged User` is allowed to obtain some additional details
        about the targeted :term:`User` of the request path if it corresponds to itself.
        See :envvar:`MAGPIE_LOGGED_PERMISSION` and :ref:`Route Access` for further details.

.. envvar:: MAGPIE_ANONYMOUS_USER

    (Default: ``"anonymous"``)

    Name of the default :term:`User` that represents non logged-in user (ie: invalid or no :term:`Authentication`
    token provided). This :term:`User` is used to manage :term:`Public` access to :term:`Service` and :term:`Resource`.

.. envvar:: MAGPIE_ANONYMOUS_PASSWORD

    [|constant|_]
    (Value: ``${MAGPIE_ANONYMOUS_USER}``)

    Password of the default unauthenticated :term:`User`.
    This value is not modifiable directly and is available only for preparation of the default user on startup.

.. envvar:: MAGPIE_ANONYMOUS_EMAIL

    (Default: ``"${MAGPIE_ANONYMOUS_USER}@mail.com"``)

    Email of the default unauthenticated :term:`User`.

.. envvar:: MAGPIE_ANONYMOUS_GROUP

    [|constant|_]
    (Value: ``${MAGPIE_ANONYMOUS_USER}``)

    Special :term:`Group` name that defines :ref:`Public Access` functionalities. All users are automatically member
    of this :term:`Public` :term:`Group` to obtain :ref:`Inherited Permissions`.

    This parameter is enforced to be equal to :envvar:`MAGPIE_ANONYMOUS_USER`. It is preserved for backward
    compatibility of migration scripts and external libraries that specifically refer to this parameter.

    .. versionchanged:: 2.0
        The :term:`Group` generated by this configuration cannot be modified to remove :term:`User` memberships or
        change other metadata associated to it.

    .. warning::
        To set :term:`Public` permissions, one should always set them on this :term:`Group` instead of directly on
        :envvar:`MAGPIE_ANONYMOUS_USER` as setting them directly on that :term:`User` will cause unexpected behaviours.
        See :ref:`Public Access` section for full explanation.

.. envvar:: MAGPIE_EDITOR_GROUP

    (Default: ``"editors"``)

    *Unused for the moment.*

.. envvar:: MAGPIE_USERS_GROUP

    (Default: ``"users"``)

    Name of a generic :term:`Group` created to associate registered :term:`User` memberships in the application.

    .. versionchanged:: 2.0
        New :term:`User` are **NOT** automatically added to this :term:`Group` anymore. This :term:`Group` remains
        available for testing and backward compatibility reasons, but doesn't have any special connotation and can be
        modified just as any other normal :term:`Group`.

        Prior versions of `Magpie` were adding every new :term:`User` to that :term:`Group` which made it no
        different than the behaviour fulfilled by :envvar:`MAGPIE_ANONYMOUS_GROUP` which they are also member of.
        Since :envvar:`MAGPIE_USERS_GROUP` has no special meaning and is modifiable at any time (e.g.: users could be
        removed from it), it could not even be employed to ensure provision of permissions applied to all users
        (its original purpose), which is also equivalent to functionalities provided with :term:`Public` permissions
        inherited by :envvar:`MAGPIE_ANONYMOUS_GROUP` that is more specifically handled by `Magpie` for this purpose.

.. envvar:: MAGPIE_GROUP_NAME_MAX_LENGTH

    [|constant|_, :class:`int`]
    (Value: ``64``)

    Maximum length to consider a :term:`Group` name as valid.
    Any name specified during creation will be forbidden if longer.

.. envvar:: MAGPIE_USER_NAME_MAX_LENGTH

    [|constant|_, :class:`int`]
    (Value: ``64``)

    Maximum length to consider a :term:`User` name as valid.
    Any name specified during creation will be forbidden if longer.

    .. warning::
        This value **MUST NOT** be greater than the token length used to identify a :term:`User` to preserve internal
        functionalities.

.. envvar:: MAGPIE_PASSWORD_MIN_LENGTH

    [:class:`int`]
    (Default: ``12``)

    .. versionadded:: 2.0

    Minimum length of the password for :term:`User` creation or update.

    .. note::
        For backward-compatibility requirements, passwords are not enforced this condition during login procedure
        as shorter passwords could have been used and not yet updated for older accounts. Fulfilling this requirement
        will be mandatory for new password updates and new :term:`User` account creations.

.. envvar:: MAGPIE_DEFAULT_PROVIDER

    [|constant|_]
    (Value: ``"ziggurat"``)

    Name of the :term:`Provider` used for login. This represents the identifier that is set to define how to
    differentiate between a local sign-in procedure and a dispatched one some known :ref:`authn_providers`.


.. _config_phoenix:

Phoenix Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings provide some integration support for `Phoenix`_ in order to synchronize its service definitions with
`Magpie` services.

.. warning::
    Support of `Phoenix`_ is fairly minimal. It is preserved for historical and backward compatibility but is
    not actively tested. Please submit an `issue`_ if you use it and some unexpected behaviour is encountered.

.. envvar:: PHOENIX_USER

    (Default: ``"phoenix"``)

    Name of the user to use for :term:`Authentication` in `Phoenix`_.

.. envvar:: PHOENIX_PASSWORD

    (Default: ``"qwerty"``)

    Password of the user to use for :term:`Authentication` in `Phoenix`_.

.. envvar:: PHOENIX_HOST
    (Default: ``${HOSTNAME}"``)

    Hostname to use for `Phoenix`_ connection to accomplish :term:`Authentication` and :ref:`Service Synchronization`.

.. envvar:: PHOENIX_PORT

    [:class:`int`]
    (Default: ``8443``)

    Port to use for `Phoenix`_ connection to accomplish :term:`Authentication` and :ref:`Service Synchronization`.

.. envvar:: PHOENIX_PUSH

    [:class:`bool`]
    (Default: ``True``)

    Whether to push new :ref:`Service Synchronization` settings to the referenced `Phoenix`_ connection.


.. _config_twitcher:

Twitcher Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings define parameters required by `Twitcher`_ (OWS Security Proxy) in order to interact with
`Magpie` services as :term:`Policy Enforcement Point`.


.. envvar:: TWITCHER_PROTECTED_PATH

    (Default: ``"/ows/proxy"``)

    HTTP path used to define the protected (public) base path of services registered in `Magpie` that will be served
    by an existing `Twitcher`_ proxy application after :term:`Access Control List` (ACL) verification of the
    :term:`Logged User`.

    .. note::
        Using this parameter to define `Twitcher`_'s path assumes that it resides under the same server domain as the
        `Magpie` instance being configured (ie: hostname is inferred from resolved value amongst :envvar:`MAGPIE_URL`,
        :envvar:`MAGPIE_HOST`, :envvar:`TWITCHER_HOST` and :envvar:`HOSTNAME` settings or environment variables).

  .. warning::
    Path is intended to be employed with `Twitcher`_ residing side-by-side with `Magpie`. Therefore, prefix
    ``/twitcher`` is added unless already explicitly provided. To employ another path without prefix, consider
    instead providing it with the full URL using :envvar:`TWITCHER_PROTECTED_URL` parameter.

.. envvar:: TWITCHER_HOST

    (Default: ``None``)

    .. versionadded:: 2.0

    Specifies the explicit hostname to employ in combination with :envvar:`TWITCHER_PROTECTED_PATH` to form the
    complete base service protected URL. Ignored if :envvar:`TWITCHER_PROTECTED_URL` was provided directly.
    If not provided, hostname resolution falls back to using :envvar:`HOSTNAME` environment variable.

    .. note::
        The resulting URL will take the form ``https://{TWITCHER_HOST}[/twitcher]{TWITCHER_PROTECTED_PATH}`` to imitate
        the resolution of :envvar:`TWITCHER_PROTECTED_URL` considering provided :envvar:`TWITCHER_PROTECTED_PATH`.

.. envvar:: TWITCHER_PROTECTED_URL

    (Default: *see note*)

    Defines the protected (public) full base URL of services registered in `Magpie`. This setting is mainly to allow
    specifying an alternative domain where a remote `Twitcher`_ instance could reside.

    .. note::
        When not provided, attempts to infer the value by combining the environment variable :envvar:`HOSTNAME` or
        :envvar:`TWITCHER_HOSTNAME`, and an optional ``/twitcher`` prefix (as needed to match incoming request) and the
        value provided by :envvar:`TWITCHER_PROTECTED_PATH`.


Please note that although `Twitcher`_ URL references are needed to configure interactive parameters with `Magpie`, the
employed `Twitcher`_ instance will also need to have access to `Magpie`'s database in order to allow proper
:term:`Service` resolution with :class:`magpie.adapter.magpieservice.MagpieServiceStore`. Appropriate database
credentials must therefore be shared between the two services, as well as :envvar:`MAGPIE_SECRET` value in order for
successful completion of the handshake during :term:`Authentication` procedure of the request :term:`User` token.


.. _config_postgres_settings:

Postgres Settings
~~~~~~~~~~~~~~~~~~~~~

Following settings define parameters required to define the `PostgreSQL`_ database connection employed by `Magpie` as
well as some other database-related operation settings. Settings defined by ``magpie.[variable_name]`` definitions
are available as described at the start of the `Configuration`_ section, as well as some special cases where additional
configuration names are supported where mentioned.


.. envvar:: MAGPIE_DB_MIGRATION

    [:class:`bool`]
    (Default: ``True``)

    Run database migration on startup in order to bring it up to date using `Alembic`_.


.. envvar:: MAGPIE_DB_MIGRATION_ATTEMPTS

    [:class:`int`]
    (Default: ``5``)

    Number of attempts to re-run database migration on startup in case it failed (eg: due to connection error).

.. envvar:: MAGPIE_DB_URL

    (Default: *see note*)

    Full database connection URL formatted as ``<db-type>://<user>:<password>@<host>:<port>/<db-name>``.

    Please refer to `SQLAlchemy Engine`_'s documentation for supported database implementations and their
    corresponding configuration.

    .. warning::
        Only `PostgreSQL`_ has been extensively tested with `Magpie`, but other variants *could* be applicable,
        but will most likely than not require adjustments to support advanced operations handled by
        :mod:`ziggurat_foundations`. If another database implementation would better suit your needs, do not
        hesitate to open a `new issue`_ for potential PR integration.

    .. note::
        By default, ``postgresql`` database connection URL is inferred by combining following ``MAGPIE_POSTGRES_<>``
        parameters if the value was not explicitly provided.

.. envvar:: MAGPIE_POSTGRES_USERNAME

    (Default: ``"magpie"``)

    Database connection username to retrieve `Magpie` data stored in `PostgreSQL`_.

    .. versionchanged:: 1.9
        On top of :envvar:`MAGPIE_POSTGRES_USERNAME`, environment variable :envvar:`POSTGRES_USERNAME` and setting
        ``postgres.username`` are all supported interchangeably. For backward compatibility, all above variants with
        ``user`` instead of ``username`` (with corresponding lower/upper case) are also verified for potential
        configuration if no prior parameter was matched. The lookup order of each name variant is as presented,
        while also keeping the setting name priority over an equivalent environment variable name.

.. envvar:: MAGPIE_POSTGRES_PASSWORD

    (Default: ``"qwerty"``)

    Database connection password to retrieve `Magpie` data stored in `PostgreSQL`_.

    .. versionchanged:: 1.9
        Environment variable :envvar:`POSTGRES_PASSWORD` and setting ``postgres.password`` are also supported if not
        previously identified by their `Magpie`-prefixed variants.

.. envvar:: MAGPIE_POSTGRES_HOST

    (Default: ``"postgres"``)

    Database connection host location to retrieve `Magpie` data stored in `PostgreSQL`_.

    .. versionchanged:: 1.9
        Environment variable :envvar:`POSTGRES_HOST` and setting ``postgres.host`` are also supported if not previously
        identified by their `Magpie`-prefixed variants.

.. envvar:: MAGPIE_POSTGRES_PORT

    [:class:`int`]
    (Default: ``5432``)

    Database connection port to retrieve `Magpie` data stored in `PostgreSQL`_.

    .. versionchanged:: 1.9
        Environment variable :envvar:`POSTGRES_PORT` and setting ``postgres.port`` are also supported if not previously
        identified by their `Magpie`-prefixed variants.

.. envvar:: MAGPIE_POSTGRES_DB

    (Default: ``"magpie"``)

    Name of the database located at the specified connection to retrieve `Magpie` data stored in `PostgreSQL`_.

    .. versionchanged:: 1.9
        Environment variable :envvar:`POSTGRES_DB` and setting ``postgres.db``, as well as the same variants with
        ``database`` instead of ``db``, are also supported if not previously identified by their `Magpie`-prefixed
        variants.


.. _config_auth_github:

GitHub Settings
~~~~~~~~~~~~~~~~~

To use `GitHub_AuthN`_ authentication provider, variables :envvar:`GITHUB_CLIENT_ID` and :envvar:`GITHUB_CLIENT_SECRET`
must be configured. These settings correspond to the values retrieved from following steps described in
`Github_OAuthApp`_.

Furthermore, the callback URL used for configuring the OAuth application on GitHub must match the running `Magpie`
instance URL. For this reason, the values of :envvar:`MAGPIE_URL`, :envvar:`MAGPIE_HOST` and :envvar:`HOSTNAME` must
be considered.

.. seealso::
    Refer to :ref:`authn_requests` and :ref:`authn_providers` for details.

.. _config_auth_wso2:

WSO2 Settings
~~~~~~~~~~~~~~~~~

To use `WSO2`_ authentication provider, following variables must be set:

- :envvar:`WSO2_HOSTNAME`
- :envvar:`WSO2_CLIENT_ID`
- :envvar:`WSO2_CLIENT_SECRET`
- :envvar:`WSO2_CERTIFICATE_FILE`
- :envvar:`WSO2_SSL_VERIFY`

To configure your `Magpie` instance as a trusted application for ``WSO2`` (and therefore retrieve values of above
parameters), please refer to |WSO2_doc|_.

.. seealso::
    Refer to :ref:`authn_requests` and :ref:`authn_providers` for details.


.. _config_user_register_approval:

User Registration and Approval Configuration
-----------------------------------------------

.. versionadded:: 3.13

This section describes the relevant details regarding the activation of settings
:envvar:`MAGPIE_USER_REGISTRATION_ENABLED` and :envvar:`MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED`.
If those settings are not defined, or are explicitly set to ``False``, all other options can be safely ignored.

.. note::
    When any of the above parameters are enabled, the :ref:`config_app_settings` regarding ``SMTP`` server
    and ``EMAIL`` options must also be defined.

All details regarding the procedures of registration and approval of user accounts are defined
in section :ref:`user_registration`.

Following are the full description of all configuration parameters employed by the :term:`User` registration and
approval procedures.


.. envvar:: MAGPIE_USER_REGISTRATION_ENABLED

    [:class:`bool`]
    (Default: ``False``)

    .. versionadded:: 3.13

    Specifies whether `Magpie` should provide :term:`User` self-registration endpoints on ``/register/users`` for
    the API and ``/ui/register/users`` for the UI and enabled the registration procedure.

    .. seealso::
        See section :ref:`user_registration` for further details about this process.

    When enabled, all other configuration regarding SMTP and EMAIL :ref:`config_app_settings` must also be defined
    to properly send notification and validation email during registration.

    The default value of this configuration setting is to preserve the original behavior of `Magpie` where no such
    :term:`User` self-registration is possible. Therefore, the option must be explicitly defined to activate it.

    .. warning::
        **Security Notice**

        Under normal operation (when disabled), `Magpie` can take advantage of stronger security by obfuscation
        as the ``user_name`` component is not accessible by any means other than administrator-level users.
        It is therefore hidden away from public view and acts as stronger credentials.

        When this option is enabled, both the ``user_name`` and ``email`` of existing users become *indirectly*
        accessible for validation purposes, to avoid account conflicts during user registration. When enabling
        this option, the developer or server maintainer must be aware of these consideration.

        For best security result, the setting should be activated only when the feature is required, and that
        ``user_name``/``email`` information is deemed adequate for potential public visibility, hence why the
        option is disabled by default. This is a design choice for respective servers and platforms.

.. envvar:: MAGPIE_USER_REGISTRATION_SUBMISSION_EMAIL_TEMPLATE

    (Default: |email_ur_submission_mako|_)

    .. versionadded:: 3.13

    Path to a `Mako Template`_ file providing custom email format to send notification email to
    the :term:`Pending User` following submission of a new :ref:`user_registration`.

    When overridden with a custom email format, the contents should provide sufficient details indicating to
    the :term:`Pending User` that its submitted email must be confirmed by visiting the link contained in that email.
    The confirmation URL would validate that emails can indeed be received by that :term:`Pending User` to the
    submitted address be notified of future events.

    The default template provides details about available template arguments.

.. envvar:: MAGPIE_USER_REGISTRATION_NOTIFY_ENABLED

    [:class:`bool`]
    (Default: ``False``)

    .. versionadded:: 3.13

    Controls whether a notification email should be sent to :envvar:`MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_RECIPIENT`
    once a :term:`Pending User` successfully *completed* the registration process.

    This can be used for example when no administrator validation is required
    (i.e.: :envvar:`MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED` is ``False``), but that some platform manager still
    want to receive notices of any users that registered to its service.

    .. note::
        Enabling this option at the same time as :envvar:`MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED` while using the
        same email for both *approval* and *notification* could lead to noisy emails expeditions as approving
        administrators would be immediately notified of their own action of approving the user registration.
        Different emails can be set to communicate relevant notifications to intended parties.
        It is up to the developer to properly configure how verbose and to whom those emails should be addressed to.

.. envvar:: MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_RECIPIENT

    .. versionadded:: 3.13

    Email address where emails with contents defined by :envvar:`MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_TEMPLATE` should
    be sent to when :envvar:`MAGPIE_USER_REGISTRATION_NOTIFY_ENABLED` was activated.

.. envvar:: MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_TEMPLATE

    (Default: |email_ur_notify_mako|_)

    .. versionadded:: 3.13

    Path to a `Mako Template`_ file providing custom email format to send notification email following completion of
    a new :ref:`user_registration`. The default template provides details about available template arguments.

    A custom body must contain all relevant details defined in the default template to ensure basic functionalities
    of the :ref:`user_registration` workflow can be accomplished. The logic of the message content is left at the
    discretion of the developer if customized.

.. envvar:: MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED

    [:class:`bool`]
    (Default: ``False``)

    .. versionadded:: 3.13

    Specifies whether administrator approval is required to resume :ref:`user_registration`.

    This setting is relevant only if :envvar:`MAGPIE_USER_REGISTRATION_ENABLED` was also activated.
    When enabled and following email *confirmation* by the :term:`Pending User`
    (see :envvar:`MAGPIE_USER_REGISTRATION_SUBMISSION_EMAIL_TEMPLATE`), an email using following configuration options
    will be sent to notify the administrator authority that :term:`Pending User` approval is awaiting their validation.

    Approval process is bypassed if this setting is disabled, meaning that :term:`Pending User` account will be
    immediately and automatically approved as soon as their email was validated, without any administrator intervention.

.. envvar:: MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_RECIPIENT

    .. versionadded:: 3.13

    Email of the *administrator* to which a notification is sent using the body defined by
    :envvar:`MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_TEMPLATE`, when a new user registration was requested.

    The email employed for this parameter can be toward any target, including an email that does not correspond to any
    :term:`User` in the `Magpie` database. For example, that email could be for a shared user support team that replies
    to those requests. Note that to validate the user registration though, valid administrative-level :term:`User` with
    matching credentials will be required to complete the process.

.. envvar:: MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_TEMPLATE

    (Default: |email_ur_approval_mako|_)

    .. versionadded:: 3.13

    Path to a `Mako Template`_ file providing custom email format to send notification email to
    :envvar:`MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_RECIPIENT` following a submitted user registration
    that must be *approved* or *declined* by the administrator.

    When overridden with a custom email format, the contents should provide sufficient details indicating to
    the administrator which :term:`Pending User` requested a new account registration, and links where it can
    review it to be *approved* or *declined*.

    The default template provides details about available template arguments.

.. envvar:: MAGPIE_USER_REGISTRATION_APPROVED_EMAIL_TEMPLATE

    (Default: |email_ur_approved_mako|_)

    .. versionadded:: 3.13

    Path to a `Mako Template`_ file providing custom email format to send an email to the
    :term:`Pending User` that initially submitted the user registration to notify them that the registration
    process was successfully approved and completed, and that their account is active starting from that moment.

    The default template provides details about available template arguments.

    .. note::
        This email template is employed regardless of value defined for
        setting :envvar:`MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED`. When administrator approval is enabled, the email
        will be sent only after the account was approved. Otherwise, it is sent as soon as email conformation is
        obtained from the :term:`Pending User`. Parameter ``approval_required`` is provided to generate alternative
        `Mako Template`_ contents in case different messages should be sent for each situation.

.. envvar:: MAGPIE_USER_REGISTRATION_DECLINED_EMAIL_TEMPLATE

    (Default: |email_ur_declined_mako|_)

    .. versionadded:: 3.13

    Path to a `Mako Template`_ file providing custom email format to send an email to the
    :term:`Pending User` that initially submitted the user registration to notify them of that their
    user registration request was declined by the administrator following approval process.

    The default template provides details about available template arguments.

.. _config_user_group_assignment:

User-Group Assignment Configuration
-----------------------------------

.. versionadded:: 3.17

Following are the full description of all configuration parameters employed by the :term:`User`-:term:`Group` assignment
procedures, in the case of a :term:`Group` that requires terms and conditions validation by the :term:`User`.

.. envvar:: MAGPIE_GROUP_TERMS_SUBMISSION_EMAIL_TEMPLATE

    (Default: |email_uga_submission_mako|_)

    .. versionadded:: 3.17

    Path to a `Mako Template`_ file providing custom email format to send notification email to the :term:`User`
    following submission of the :term:`User` assignment to a :term:`Group` that requires accepting terms and conditions.

    When overridden with a custom email format, the contents should provide sufficient details indicating to the
    :term:`User` that they must accept the :term:`Group`'s terms and conditions to join it, and that confirmation is
    accomplished by visiting the link contained in that email. The confirmation URL would validate that the :term:`User`
    accepts the terms and conditions, and would proceed with the assignment of the :term:`User` to the :term:`Group`.
    The contents of the email should also include the terms and conditions of the :term:`Group`.

    The default template provides details about available template arguments.

.. envvar:: MAGPIE_GROUP_TERMS_APPROVED_EMAIL_TEMPLATE

    (Default: |email_uga_approved_mako|_)

    .. versionadded:: 3.17

    Path to a `Mako Template`_ file providing custom email format to send an email to the :term:`User` related to a
    :term:`User`-:term:`Group` assignment to notify them that the terms and conditions were accepted, and that their
    account is now a member of the requested :term:`Group`.

    The default template provides details about available template arguments.

.. _config_webhook:

Webhook Configuration
------------------------

.. versionadded:: 3.6
    The concept of :term:`Webhook` is introduced only following this version, and further improved in following ones.

.. |webhooks_section| replace:: ``webhooks``

A |webhooks_section| section can be added to the :ref:`config_file`. This section defines a list of URLs and request
parameters that should be called following or during specific events, such as but not limited to, creating or deleting
a :term:`User`.

.. note::
    Webhook requests are asynchronous, so `Magpie` might execute other requests before the webhooks requests are
    completed and processed.

.. seealso::
    See :ref:`config_file` for a minimal example of where and how to define the |webhooks_section| section.

Each :term:`Webhook` implementation provides different sets of parameters according to its |webhook_param_action|_.
Those parameters can be employed to fill a template request payload defined under |webhook_param_payload|_.
See :class:`magpie.api.webhook.WebhookAction` and below sub-sections for supported values.

To register any :term:`Webhook` to be called at runtime upon corresponding events, following parameters must be defined.
Configuration parameters are all required unless explicitly indicated to have a default value.

.. _webhook_param_name:
.. |webhook_param_name| replace:: ``name``

- | |webhook_param_name|_

  The name of the :term:`Webhook` for reference.

  It is not required for this name to be unique, but it is recommended for reporting and reference purposes.
  If duplicates are found, a warning will be emitted, but all entries will still be registered.

.. _webhook_param_action:
.. |webhook_param_action| replace:: ``action``

- | |webhook_param_action|_
  | (Values: one of :class:`magpie.api.webhook.WebhookAction`)

  The action event defining when the corresponding :term:`Webhook` must be triggered for execution.

  .. seealso::
    :ref:`config_webhook_actions` for details about each implementation.

.. _webhook_param_method:
.. |webhook_param_method| replace:: ``method``

- | |webhook_param_method|_
  | (Values: one of :data:`magpie.api.webhook.WEBHOOK_HTTP_METHODS`)

  The HTTP method used for the :term:`Webhook` request.

.. _webhook_param_url:
.. |webhook_param_url| replace:: ``url``

- | |webhook_param_url|_

  A valid HTTP(S) URL location where the triggered :term:`Webhook` request will be sent.

.. _webhook_param_format:
.. |webhook_param_format| replace:: ``format``

- | |webhook_param_format|_
  | (Default: ``"json"``, Value: one of :data:`magpie.utils.FORMAT_TYPE_MAPPING`)

  A valid format definition of the content type of |webhook_param_payload|_.

.. _webhook_param_payload:
.. |webhook_param_payload| replace:: ``payload``

- | |webhook_param_payload|_
  | (Default: ``None``)

  Structure of the payload that will be sent in the request body of the triggered :term:`Webhook`.
  The payload can be anything between a literal string or a JSON/YAML formatted structure.

  .. versionchanged:: 3.12
    If the field is undefined or resolved as ``None``, it will be accepted for request with an empty body.

  .. note::
    The payload can employ parameters that contain template variables using brace characters ``{{<variable>}}``.
    Applicable ``{{<variable>}}`` substitution are respective to each webhook |webhook_param_action|_, as presented in
    :ref:`config_webhook_actions`.

  .. seealso::
    See :ref:`config_webhook_template` for a more concrete example of templated |webhook_param_payload|_ definition.


.. _config_webhook_actions:

Webhook Actions
------------------------

.. default location to quickly reference items without the explicit and long prefix
.. using the full name when introducing the element (to make the location obvious), then reuse shorthand variant
.. py:currentmodule:: magpie.api.webhooks

This section presents the supported :term:`Webhook` |webhook_param_action|_ values that can be registered and
corresponding template parameters available in each case to generate the payload.

.. _webhook_user_create:

User Creation
~~~~~~~~~~~~~~~

.. list-table::
    :header-rows: 0
    :stub-columns: 1
    :widths: 10,90

    * - Action
      - :attr:`WebhookAction.CREATE_USER`
    * - Parameters
      - ``{{user.name}}``, ``{{user.id}}``, ``{{user.email}}``, ``{{callback_url}}``

Triggered whenever a :term:`User` gets successfully created, using a ``POST /users`` request.

The :term:`User` details are provided for reference as needed for the receiving external web application defined by the
configured |webhook_param_url|_.

The ``callback_url`` serves as follow-up endpoint, should the registered external application need it, to request using
HTTP ``GET`` method (no body) that `Magpie` sets the :term:`User` account status as erroneous. That :term:`User` would
then be affected with ``status`` value :attr:`magpie.models.UserStatuses.WebhookError`. The ``callback_url``
location will be available until called or expired according to :envvar:`MAGPIE_TOKEN_EXPIRE` setting. When no request
is sent to the ``callback_url``, the created :term:`User` is assumed valid and its account is attributed
:attr:`magpie.models.UserStatuses.OK` status.

.. _webhook_user_delete:

User Deletion
~~~~~~~~~~~~~~~

.. list-table::
    :header-rows: 0
    :stub-columns: 1
    :widths: 10,90

    * - Action
      - :attr:`WebhookAction.DELETE_USER`
    * - Parameters
      - ``{{user.name}}``, ``{{user.id}}``, ``{{user.email}}``

Triggered whenever a :term:`User` gets successfully deleted, using a ``DELETE /users/{user_name}`` request.


.. _webhook_user_update_status:

User Status Update
~~~~~~~~~~~~~~~~~~~

.. list-table::
    :header-rows: 0
    :stub-columns: 1
    :widths: 10,90

    * - Action
      - :attr:`WebhookAction.UPDATE_USER_STATUS`
    * - Parameters
      - ``{{user.name}}``, ``{{user.id}}``, ``{{user.status}}``, ``{{callback_url}}``

Triggered whenever a :term:`User` status gets successfully updated, using a ``PATCH /users/{user_name}`` request.

This event **DOES NOT** apply to changes of :term:`User` status caused by callback URL request received following
a :ref:`webhook_user_create` event.

The ``callback_url`` in this case can be requested with ``GET`` method (no body) to ask `Magpie` to reset the just
updated :term:`User` account status to :attr:`magpie.models.UserStatuses.WebhookError`. This :term:`Webhook`
can be employed to retry an external operation of the registered application, by triggering status updates, and only
consider the complete operation successful when no further ``callback_url`` requests are received.


.. _webhook_permission_updates:

Permission Updates
~~~~~~~~~~~~~~~~~~~~~~~~

Below :term:`Webhook` implementations can all be configured for any combination of creation/deletion of a
:term:`Permission` for a :term:`User` or :term:`Group`, and targeting either a :term:`Service` or a :term:`Resource`.

.. list-table::
    :header-rows: 0
    :stub-columns: 1
    :widths: 10,90

    * - Action
      - :attr:`WebhookAction.CREATE_USER_PERMISSION`, :attr:`WebhookAction.DELETE_USER_PERMISSION`,
        :attr:`WebhookAction.CREATE_GROUP_PERMISSION`, :attr:`WebhookAction.DELETE_GROUP_PERMISSION`
    * - Parameters
      - ``{{user.name}}`` or ``{{group.name}}``, ``{{user.id}}`` or ``{{group.id}}``,
        ``{{resource.id}}``, ``{{resource.type}}``, ``{{resource.name}}``, ``{{resource.display_name}}``,
        ``{{service.name}}``, ``{{service.type}}``, ``{{service.public_url}}``, ``{{service.sync_type}}``,
        ``{{permission.name}}``, ``{{permission.access}}``, ``{{permission.scope}}``, ``{{permission}}``

The parameters available for the |webhook_param_payload|_ are very similar in each case, except that they are adjusted
accordingly to the :term:`User` or :term:`Group` the modification applies to.

The :term:`Resource` details are available regardless of if it refers to a :term:`Service` or any children
:term:`Resource`. The value of ``{{resource.type}}`` will be ``"service"`` if the reference was a :term:`Service`.
The ``{{service.<field>}}`` parameters will only be defined if the target was indeed a :term:`Service`, and will
be ``null`` otherwise.

The created or deleted :term:`Permission` details are available with different formats. The ``{{permission.name}}``,
``{{permission.access}}`` and ``{{permission.scope}}`` correspond to the same fields presented in
:ref:`permission_modifiers` chapter. The ``permission`` parameter corresponds to the *explicit* name,
as defined in :ref:`permission_representations`.


.. _config_webhook_template:

Webhook Template Payload
------------------------

Following subsections demonstrate common substitution patterns for templated request payload according to desired
content format.

JSON Payload
~~~~~~~~~~~~~~~~~

This is a minimal example to demonstrate how the :term:`Webhook` template payload functionality can help customize
requests sent following given event triggers. For simplicity, lets assume that a ``demo`` :term:`Webhook` provides
two parameters, namely ``user_name = "demo"`` and ``user_id = 123``. Let's assume the following configuration was
defined and loaded by `Magpie`.

.. code-block:: YAML

    webhooks:
      - name: demo_webhook
        action: demo
        method: POST
        url: https://receiving-middleware.example.com
        payload:
          user:
            name: "{{user.name}}"
            id: "{{user.id}}"
            str: "'{{user.id}}'"
          msg: Hello {{user.name}}, your ID is {{user.id}}


Upon trigger of the ``demo`` event, the above :term:`Webhook` definition would result in a request sent with the
following JSON |webhook_param_payload|_ contents.

.. code-block:: JSON

    {
        "user": {
            "name": "demo",
            "id": 123,
            "str": "123"
        },
        "msg": "Hello demo, your ID is 123"
    }

As presented above, the ``"{{user.name}}"`` from the template gets substituted by the corresponding ``"demo"`` value.
Similarly, ``"{{user.id}}"`` is replaced by ``123``. An important thing to notice is that value types are preserved,
which is why the ``id`` field is an integer since that corresponding parameter is an integer in `Magpie`. Using the
specification ``"'{{user.id}}'"`` (with additional single quotes) instead tells the template parser to replace the
value by its string representation. It is also possible to define any combination of parameters as indicated in the
``msg`` field of the example, and for any kind of structure, as long as JSON/YAML valid definitions are respected.

It is important to take into consideration how YAML parsing operates in this case. Quotes are *not mandatory*
everywhere, such as for values where inferred type is guaranteed to be strings as for ``msg``, but this can rapidly
become a problem in other cases such as within an object definition or for field keys. It is therefore recommended to
employ quotes whenever possible to remove ambiguity.

Another example where YAML parsing must be carefully considered is as in the following definition that could produce
an unexpected outcome.

.. code-block:: YAML

    payload:
      user:
        - {user_name}


This would generate the following JSON content.


.. code-block:: JSON

    {
        "user": {
            "user_name": null
        }
    }


This is because YAML interprets ``{user_name}`` within an array list as an object with a field named ``user_name`` and
no corresponding value (i.e.: ``null``). For this reason, `Magpie` employs the double-braced ``{{<variable>}}`` format
to remove this ambiguity. An unknown parameter value defined in |webhook_param_payload|_ during substitution or an ill
defined configuration at application startup would immediately generate an error since YAML parsing will not correctly
understand nor be able to infer the format of the double-braces definitions, instead of silently failing. When using a
parameter by themselves, such as in the top example's ``"{{user.name}}"`` and ``"{{user.id}}"`` values, quotes will
usually be required.

String Payload
~~~~~~~~~~~~~~~~~~~

Literal string body can also be employed using templated |webhook_param_payload|_ definition to form a custom
:term:`Webhook` request content format. To do so, one only needs to define the payload as a string. For convenience,
multiline character (e.g.: ``|``) can be employed to ease *literal* formatting of the content as in the below example.

.. code-block:: YAML

    payload: |
      param: {{user.name}}
      quote: "{{user.id}}"


This would produce the literal string output as below.

.. code-block:: text

    param: demo
    quote: "123"


It is important to consider that in this case, because the whole |webhook_param_payload|_ is a string, explicit quotes
and newlines defined in its value will remain as is, according to the selected multiline character. Also, this kind of
:term:`Webhook` should most probably define the appropriate |webhook_param_format|_ value if the default ``json`` is
not the desired ``Content-Type``, as `Magpie` will not attempt to infer the content structure to generate the request.

Advanced Payload Substitutions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An extensive representation of supported template replacement patterns is presented in the following
|func_test_webhook|_ function. As presented, the resulting |webhook_param_payload|_ can therefore be
extensively customized to match exactly the desired format.

.. because 'tests' are not included in autodoc, reference doesn't produce a link, so provide it via repository
.. _func_test_webhook: https://github.com/Ouranosinc/Magpie/blob/master/tests/test_webhooks.py
.. |func_test_webhook| replace:: :func:`tests.test_webhooks.test_webhook_template_substitution`

.. include starting at line of the function definition to skip unnecessary display of decorated test markers
.. literalinclude:: ../tests/test_webhooks.py
    :language: python
    :pyobject: test_webhook_template_substitution
    :linenos:
    :lines: 3-
