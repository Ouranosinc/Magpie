.. :changelog:

History
=======

Unreleased
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add ``MAGPIE_DB_URL`` configuration parameter to define a database connection with full URL instead of individual
  parts (notably ``MAGPIE_POSTGRES_<>`` variables).
* add ``bandit`` security code analysis and apply some detected issues (#168).
* add more code linting checks using various test tools.
* add smoke test of built docker image to `Travis-CI` pipeline.
* bump ``alembic>=1.3.0`` to remove old warnings and receive recent fixes.
* move ``magpie.utils.SingletonMeta`` functionality from adapter to reuse it in ``null`` test checks.
* rename ``resource_tree_service`` and ``remote_resource_tree_service`` to their uppercase equivalents.
* removed module ``magpie.definitions`` in favor of directly importing appropriate references as needed.
* improve ``make help`` targets descriptions.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix incorrectly installed ``authomatic`` library following update of reference branch
  (https://github.com/fmigneault/authomatic/tree/httplib-port) with ``master`` branch merged update
  (https://github.com/authomatic/authomatic/pull/195/commits/d7897c5c4c20486b55cb2c70724fa390c9aa7de6).
* fix documentation links incorrectly generated for `readthedocs` pages.
* fix missing or incomplete configuration documentation details.
* fix many linting issues detected by integrated tools.

1.7.4 (2019-12-03)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~

* add sorting by name of configuration files (permissions/providers) when loaded from a containing directory path.
* add `readthedocs` references to README.

1.7.3 (2019-11-20)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix 500 error when getting user's services on ``/users/{user_name}/services``.

1.7.2 (2019-11-15)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix ``gunicorn>=20.0.0`` breaking change not compatible with alpine: pin ``gunicorn==19.9.0``.

1.7.1 (2019-11-12)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix resource sync process and update cron job running it (#226).
* fix configuration files not loaded from directory by application due to more restrictive file check.
* fix a test validating applicable user resources and permissions that could fail if `anonymous` permissions where
  generated into the referenced database connection (eg: from loading a ``permissions.cfg`` or manually created ones).

1.7.0 (2019-11-04)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add ``docs/configuration.rst`` file that details all configuration settings that are employed by ``Magpie`` (#180).
* add more details about basic usage of `Magpie` in ``docs/usage.rst``.
* add details about external provider setup in ``docs/configuration`` (#173).
* add specific exception classes for ``register`` sub-package operations.
* add ``PHOENIX_HOST`` variable to override default ``HOSTNAME`` as needed.
* add support of ``MAGPIE_PROVIDERS_CONFIG_PATH`` and ``MAGPIE_PERMISSIONS_CONFIG_PATH`` pointing to a directory to
  load multiple similar configuration files contained in it.
* add environment variable expansion support for all fields within ``providers.cfg`` and ``permissions.cfg`` files.

1.6.3 (2019-10-31)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix the alembic database version number in the /version route (#165)
* fix failing migration step due to missing ``root_service_id`` column in database at that time and version.

1.6.2 (2019-10-04)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix a bug in ows_parser_factory that caused query parameters for wps services to be case sensitive

1.6.1 (2019-10-01)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix migration script for project-api service type

1.6.0 (2019-09-20)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add an utility script ``create_users`` for quickly creating multiple users from a list of email addresses (#219).
* add PEP8 auto-fix make target ``lint-fix`` that will correct any PEP8 and docstring problem to expected format.
* add auto-doc of make target ``help`` message
* add ACL caching option and documentation (#218)

1.5.0 (2019-09-09)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* use singleton interface for ``MagpieAdapter`` and ``MagpieServiceStore`` to avoid class recreation and reduce request
  time by `Twitcher` when checking for a service by name.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix issue of form submission not behaving as expected when pressing ``<ENTER>`` key (#209)
* fix 500 error when deleting a service resource from UI (#195)

1.4.0 (2019-08-28)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* apply ``MAGPIE_ANONYMOUS_GROUP`` to every new user to ensure they can access public resources when they are logged in
  and that they don't have the same resource permission explicitly set for them

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix migration script hastily removing anonymous group permissions without handling and transferring them accordingly
* use settings during default user creation instead of relying only on environment variables, to reflect runtime usage

1.3.4 (2019-08-09)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix migration script errors due to incorrect object fetching from db [Ouranosinc/PAVICS#149]

1.3.3 (2019-07-11)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* update ``MagpieAdapter`` to use `Twitcher` version ``0.5.2`` to employ HTTP status code fixes and additional
  API route details
  - https://github.com/bird-house/twitcher/pull/79
  - https://github.com/bird-house/twitcher/pull/84

1.3.2 (2019-07-09)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add ``use_tweens=True`` to ``request.invoke_subrequest`` calls in order to properly handle the nested database
  transaction states with the manager (#203). Automatically provides ``pool_threadlocal`` functionality added in
  ``1.3.1`` as per implementation of ``pyramid_tm`` (#201).

1.3.1 (2019-07-05)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add ``pool_threadlocal=True`` setting for database session creation to allow further connections across workers
  (see #201, #202 for further information)

1.3.0 (2019-07-02)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* move ``get_user`` function used specifically for `Twitcher` via ``MagpieAdapter`` where it is employed.
* remove obsolete, unused and less secure code that converted a token to a matching user by ID.
* avoid overriding a logger level specified by configuration by checking for ``NOTSET`` beforehand.
* add debug logging of Authentication Policy employed within ``MagpieAdapter``
* add debug logging of Authentication Policy at config time for both `Twitcher` and `Magpie`
* add debug logging of Cookie identification within ``MagpieAdapter``
* add route ``/verify`` with ``POST`` request to verify matching Authentication Policy tokens retrieved between
  `Magpie` and `Twitcher` (via ``MagpieAdapter``)

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix ``MagpieAdapter`` name incorrectly called when displayed using route ``/info`` from `Twitcher`

1.2.1 (2019-06-28)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* log every permission requests.

1.2.0 (2019-06-27)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* provide some documentation about ``magpie.constants`` module behaviour.
* remove some inspection comments by using combined requirements files.
* add constant ``MAGPIE_LOG_PRINT`` (default: ``False``) to enforce printing logs to console
  (equivalent to specifying a ``sys.stdout/stderr StreamHandler`` in ``magpie.ini``, but is not enforced anymore)
* update logging config to avoid duplicate outputs and adjust code to respect specified config.
* add some typing for ACL methods

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix ``Permission`` enum vs literal string usage during ACL resolution for some services and return enums when calling
  ``ServiceInterface.permission_requested`` method.
* fix user/group permission checkboxes not immediately reflected in UI after clicking them (#160)

1.1.0 (2019-05-28)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~

* prioritize settings (ie: `magpie.ini` values) before environment variables and ``magpie.constants`` globals.
* allow specifying ``magpie.scheme`` setting to generate the ``magpie.url`` with it if the later was omitted.
* look in settings for required parameters for function ``get_admin_cookies``.
* use API definitions instead of literal strings for routes employed in ``MagpieAdapter``.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix erroneous ``Content-Type`` header retrieved from form submission getting forwarded to API requests.
* fix user name update failing because of incomplete db transaction.

1.0.0 (2019-05-24)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add ``Dockerfile.adapter`` to build and configure ``MagpieAdapter`` on top of ``Twitcher >= 0.5.0``
* add auto-bump of history version
* update history with more specific sections
* improve ``Makefile`` targets with more checks and re-using variables
* add constant alternative search of variant ``magpie.[variable_name]`` for ``MAGPIE_[VARIABLE_NAME]``
* add tests for ``get_constant`` function
* regroup all configurations in a common file located in ``config/magpie.ini``
* remove all other configuration files (``tox.ini``, ``alembic.ini``, ``logging.ini``)
* drop `Makefile` target ``test-tox``

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* use an already created configurator when calling ``MagpieAdapter.configurator_factory``
  instead of recreating it from settings to preserve potential previous setup and includes
* use default ``WPSGet``/``WPSPost`` for ``magpie.owsrequest.OWSParser`` when no ``Content-Type`` header is specified
  (``JSONParser`` was used by default since missing ``Content-Type`` was resolved to ``application/json``, which
  resulted in incorrect parsing of `WPS` requests parameters)
* actually fetch required `JSON` parameter from the request body if ``Content-Type`` is ``application/json``
* convert ``Permission`` enum to string for proper ACL comparison in ``MagpieOWSSecurity``
* fix ``raise_log`` function to allow proper evaluation against ``Exception`` type instead of ``message`` property

0.10.0 (2019-04-15)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* refactoring of literal strings to corresponding ``Permission`` enum (#167)
* change all incorrect usages of ``HTTPNotAcceptable [406]`` to ``HTTPBadRequest [400]`` (#163)
* add ``Accept`` header type checking before requests and return ``HTTPNotAcceptable [406]`` if invalid
* code formatting changes for consistency and cleanup of redundant/misguiding names (#162)
* add option ``MAGPIE_UI_ENABLED`` allowing to completely disable all ``/ui`` route (enabled by default)
* add more unittests (#74)

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix swagger responses status code and description and fix erroneous body (#126)
* fix invalid member count value returned on ``/groups/{id}`` request
* fix invalid ``DELETE /users/{usr}/services/{svc}/permissions/{perm}`` request not working

0.9.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* greatly reduce docker image size
* allow quick functional testing using sequences of local app form submissions
* add test methods for UI redirects to other views from button click in displayed page
* change resource response for generic ``resource: {<info>}`` instead of ``{resource-id}: {<info>}``
* add permissions config to auto-generate user/group rules on startup
* attempt db creation on first migration if not existing
* add continuous integration testing and deployment (with python 2/3 tests)
* ensure python compatibility for Python 2.7, 3.5, 3.6 (via `Travis-CI`)
* reduce excessive ``sqlalchemy`` logging using ``MAGPIE_LOG_LEVEL >= INFO``
* use schema API route definitions for UI calls
* use sub-requests API call for UI operations (fixes issue `#114 <https://github.com/Ouranosinc/Magpie/issues/114>`_)
* add new route ``/services/types`` to obtain a list of available service types
* add ``resource_child_allowed`` and ``resource_types_allowed`` fields in service response
* change service response for generic ``service: {<info>}`` instead of ``{service-name}: {<info>}``
* add new route ``/services/types/{svc_type}/resources`` for details about child service type resources
* error handling of reserved route keywords service `types` and current user ``MAGPIE_LOGGED_USER``
* additional tests for new routes and operations previously left unevaluated
* logging requests and exceptions according to `MAGPIE_LOG_REQUEST` and `MAGPIE_LOG_EXCEPTION` values
* better handling of ``HTTPUnauthorized [401]`` and ``HTTPForbidden [403]`` according to unauthorized view
  (invalid access token/headers or forbidden operation under view)
* better handling of ``HTTPNotFound [404]`` and ``HTTPMethodNotAllowed [405]`` on invalid routes and request methods

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix UI add child button broken by introduced ``int`` resource id type checking
* fix `Travis-CI` test suite execution and enable PEP8 lint checks
* fix yaml security issue using updated package distribution
* fix invalid conflict service name check on service update request
* fix many invalid or erroneous swagger specifications

0.8.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* update `MagpieAdapter` to match process store changes
* provide user ID on API routes returning user info

0.7.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add service resource auto-sync feature
* return user/group services if any sub-resource has permissions
* add inherited resource permission with querystring (deprecate `inherited_<>` routes warnings)
* add flag to return `effective` permissions from user resource permissions requests
* hide service private URL on non administrator level requests
* make cookies expire-able by setting ``MAGPIE_COOKIE_EXPIRE`` and provide cookie only on http
  (`JS CSRF` attack protection)
* update ``MagpieAdapter.MagpieOWSSecurity`` for `WSO2` seamless integration with Authentication header token
* update ``MagpieAdapter.MagpieProcess`` for automatic handling of REST-API WPS process route access permissions
* update ``MagpieAdapter.MagpieService`` accordingly to inherited resources and service URL changes

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fixes related to postgres DB entry conflicting inserts and validations
* fix external providers login support (validated for `DKRZ`, `GitHub` and `WSO2`)

0.6.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* add ``/magpie/api/`` route to locally display the Magpie REST API documentation
* move many source files around to regroup by API/UI functionality
* auto-generation of swagger REST API documentation
* unit tests
* validation of permitted resource types children under specific parent service or resource
* ``ServiceAPI`` to filter ``read``/``write`` of specific HTTP methods on route parts
* ``ServiceAccess`` to filter top-level route ``access`` permission of a generic service URL
* properly return values of field ``permission_names`` under ``/services/.*`` routes
* update make procedures and postgres variables specific to magpie

0.5.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* independent user/group permissions, no more 'personal' group to reflect user permissions
* service specific resources with service*-typed* resource permissions
* more verification of resources permissions under specific services
* reference to root service from each sub-resource
* inheritance of user and group permissions with different routes
* improve some routes returned codes, inputs check, and requests formats (JSON)

0.4.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* default admin permissions
* block UI view permissions of all pages if not logged in
* signout clear header to forget user
* push to Phoenix adjustments and new push button option

0.3.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* `ncWMS` support for `getmap`, `getcapabilities`, `getmetadata` on ``thredds`` resource
* `ncWMS2` added to default providers
* add `geoserverwms` service
* remove load balanced `Malleefowl` and `Catalog`
* push service provider updates to `Phoenix` on service edit or initial setup with `getcapabilities` for `anonymous`
* major update of `Magpie REST API 0.2.x documentation` to match returned codes/messages from 0.2.0 changes
* normalise additional HTTP request responses omitted from 0.2.0 (404, 500, and other missed responses)
* remove internal api call, separate login external from local, direct access to `ziggurat` login

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix UI ``"Magpie Administration"`` to redirect toward home page instead of `PAVICS` platform
* fix bug during user creation against preemptive checks
* fix issues from `0.2.x` versions

0.2.0
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Revamp HTTP standard error output format, messages, values and general error/exception handling.
* Update `Magpie REST API 0.2.0 documentation`.

0.1.1
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add edition of service URL via ``PUT /{service_name}``.

0.1.0
---------------------

* First structured release.
