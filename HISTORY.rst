.. :changelog:

History
=======

Unreleased
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Remove ``MAGPIE_ALEMBIC_INI_FILE_PATH`` configuration parameter in favor of ``MAGPIE_INI_FILE_PATH``.
* Forward ``.ini`` file provided as argument to ``MAGPIE_INI_FILE_PATH`` (e.g.: when using ``gunicorn --paste <ini>``).
* Load configuration file (previously only ``.cfg``) also using ``.yml``, ``.yaml`` and ``.json`` extensions.
* Add argument parameter for ``run_db_migration`` helper to specify the configuration ``ini`` file to employ.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Use forwarded input argument to ``MAGPIE_INI_FILE_PATH`` to execute database migration.
* Handle trailing ``/`` of HTTP path that would fail an ACL lookup of the corresponding service or resource.

1.9.1 (2020-02-20)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update adapter docker image reference to ``birdhouse/twitcher:v0.5.3``.

1.9.0 (2020-01-29)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Change database user name setting to lookup for ``MAGPIE_POSTGRES_USERNAME`` (and corresponding INI file setting)
  instead of previously employed ``MAGPIE_POSTGRES_USER``, but leave backward support if old parameter if not resolved
  by the new one.
* Add support of variables not prefixed by ``MAGPIE_`` for ``postgres`` database connection parameters, as well as
  all their corresponding ``postgres.<param>`` definitions in the INI file.

1.8.0 (2020-01-10)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``MAGPIE_DB_URL`` configuration parameter to define a database connection with full URL instead of individual
  parts (notably ``MAGPIE_POSTGRES_<>`` variables).
* Add ``bandit`` security code analysis and apply some detected issues (#168).
* Add more code linting checks using various test tools.
* Add smoke test of built docker image to `Travis-CI` pipeline.
* Bump ``alembic>=1.3.0`` to remove old warnings and receive recent fixes.
* Move ``magpie.utils.SingletonMeta`` functionality from adapter to reuse it in ``null`` test checks.
* Rename ``resource_tree_service`` and ``remote_resource_tree_service`` to their uppercase equivalents.
* Removed module ``magpie.definitions`` in favor of directly importing appropriate references as needed.
* Improve ``make help`` targets descriptions.
* Change to Apache license.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix incorrectly installed ``authomatic`` library following update of reference branch
  (https://github.com/fmigneault/authomatic/tree/httplib-port) with ``master`` branch merged update
  (https://github.com/authomatic/authomatic/pull/195/commits/d7897c5c4c20486b55cb2c70724fa390c9aa7de6).
* Fix documentation links incorrectly generated for `readthedocs` pages.
* Fix missing or incomplete configuration documentation details.
* Fix many linting issues detected by integrated tools.

1.7.4 (2019-12-03)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~

* Add sorting by name of configuration files (permissions/providers) when loaded from a containing directory path.
* Add `readthedocs` references to README.

1.7.3 (2019-11-20)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix 500 error when getting user's services on ``/users/{user_name}/services``.

1.7.2 (2019-11-15)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``gunicorn>=20.0.0`` breaking change not compatible with alpine: pin ``gunicorn==19.9.0``.

1.7.1 (2019-11-12)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix resource sync process and update cron job running it (#226).
* Fix configuration files not loaded from directory by application due to more restrictive file check.
* Fix a test validating applicable user resources and permissions that could fail if `anonymous` permissions where
  generated into the referenced database connection (eg: from loading a ``permissions.cfg`` or manually created ones).

1.7.0 (2019-11-04)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``docs/configuration.rst`` file that details all configuration settings that are employed by ``Magpie`` (#180).
* Add more details about basic usage of `Magpie` in ``docs/usage.rst``.
* Add details about external provider setup in ``docs/configuration`` (#173).
* Add specific exception classes for ``register`` sub-package operations.
* Add ``PHOENIX_HOST`` variable to override default ``HOSTNAME`` as needed.
* Add support of ``MAGPIE_PROVIDERS_CONFIG_PATH`` and ``MAGPIE_PERMISSIONS_CONFIG_PATH`` pointing to a directory to
  load multiple similar configuration files contained in it.
* Add environment variable expansion support for all fields within ``providers.cfg`` and ``permissions.cfg`` files.

1.6.3 (2019-10-31)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix the alembic database version number in the /version route (#165).
* Fix failing migration step due to missing ``root_service_id`` column in database at that time and version.

1.6.2 (2019-10-04)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix a bug in ows_parser_factory that caused query parameters for wps services to be case sensitive.

1.6.1 (2019-10-01)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix migration script for project-api service type.

1.6.0 (2019-09-20)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add an utility script ``create_users`` for quickly creating multiple users from a list of email addresses (#219).
* Add PEP8 auto-fix make target ``lint-fix`` that will correct any PEP8 and docstring problem to expected format.
* Add auto-doc of make target ``help`` message.
* Add ACL caching option and documentation (#218).

1.5.0 (2019-09-09)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Use singleton interface for ``MagpieAdapter`` and ``MagpieServiceStore`` to avoid class recreation and reduce request
  time by `Twitcher` when checking for a service by name.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix issue of form submission not behaving as expected when pressing ``<ENTER>`` key (#209).
* Fix 500 error when deleting a service resource from UI (#195).

1.4.0 (2019-08-28)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Apply ``MAGPIE_ANONYMOUS_GROUP`` to every new user to ensure they can access public resources when they are logged in
  and that they don't have the same resource permission explicitly set for them.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix migration script hastily removing anonymous group permissions without handling and transferring them accordingly.
* Use settings during default user creation instead of relying only on environment variables, to reflect runtime usage.

1.3.4 (2019-08-09)
---------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix migration script errors due to incorrect object fetching from db [Ouranosinc/PAVICS#149].

1.3.3 (2019-07-11)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update ``MagpieAdapter`` to use `Twitcher` version ``0.5.2`` to employ HTTP status code fixes and additional
  API route details :
  - https://github.com/bird-house/twitcher/pull/79
  - https://github.com/bird-house/twitcher/pull/84

1.3.2 (2019-07-09)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``use_tweens=True`` to ``request.invoke_subrequest`` calls in order to properly handle the nested database
  transaction states with the manager (#203). Automatically provides ``pool_threadlocal`` functionality added in
  ``1.3.1`` as per implementation of ``pyramid_tm`` (#201).

1.3.1 (2019-07-05)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``pool_threadlocal=True`` setting for database session creation to allow further connections across workers
  (see #201, #202 for further information).

1.3.0 (2019-07-02)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Move ``get_user`` function used specifically for `Twitcher` via ``MagpieAdapter`` where it is employed.
* Remove obsolete, unused and less secure code that converted a token to a matching user by ID.
* Avoid overriding a logger level specified by configuration by checking for ``NOTSET`` beforehand.
* Add debug logging of Authentication Policy employed within ``MagpieAdapter``.
* Add debug logging of Authentication Policy at config time for both `Twitcher` and `Magpie`.
* Add debug logging of Cookie identification within ``MagpieAdapter``.
* Add route ``/verify`` with ``POST`` request to verify matching Authentication Policy tokens retrieved between
  `Magpie` and `Twitcher` (via ``MagpieAdapter``).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``MagpieAdapter`` name incorrectly called when displayed using route ``/info`` from `Twitcher`.

1.2.1 (2019-06-28)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Log every permission requests.

1.2.0 (2019-06-27)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Provide some documentation about ``magpie.constants`` module behaviour.
* Remove some inspection comments by using combined requirements files.
* Add constant ``MAGPIE_LOG_PRINT`` (default: ``False``) to enforce printing logs to console
  (equivalent to specifying a ``sys.stdout/stderr StreamHandler`` in ``magpie.ini``, but is not enforced anymore).
* Update logging config to avoid duplicate outputs and adjust code to respect specified config.
* Add some typing for ACL methods.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``Permission`` enum vs literal string usage during ACL resolution for some services and return enums when calling.
  ``ServiceInterface.permission_requested`` method.
* Fix user/group permission checkboxes not immediately reflected in UI after clicking them (#160).

1.1.0 (2019-05-28)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Prioritize settings (ie: `magpie.ini` values) before environment variables and ``magpie.constants`` globals.
* Allow specifying ``magpie.scheme`` setting to generate the ``magpie.url`` with it if the later was omitted.
* Look in settings for required parameters for function ``get_admin_cookies``.
* Use API definitions instead of literal strings for routes employed in ``MagpieAdapter``.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix erroneous ``Content-Type`` header retrieved from form submission getting forwarded to API requests.
* Fix user name update failing because of incomplete db transaction.

1.0.0 (2019-05-24)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``Dockerfile.adapter`` to build and configure ``MagpieAdapter`` on top of ``Twitcher >= 0.5.0``.
* Add auto-bump of history version.
* Update history with more specific sections.
* Improve ``Makefile`` targets with more checks and re-using variables.
* Add constant alternative search of variant ``magpie.[variable_name]`` for ``MAGPIE_[VARIABLE_NAME]``.
* Add tests for ``get_constant`` function.
* Regroup all configurations in a common file located in ``config/magpie.ini``.
* Remove all other configuration files (``tox.ini``, ``alembic.ini``, ``logging.ini``).
* Drop `Makefile` target ``test-tox``.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Use an already created configurator when calling ``MagpieAdapter.configurator_factory``
  instead of recreating it from settings to preserve potential previous setup and includes.
* Use default ``WPSGet``/``WPSPost`` for ``magpie.owsrequest.OWSParser`` when no ``Content-Type`` header is specified
  (``JSONParser`` was used by default since missing ``Content-Type`` was resolved to ``application/json``, which
  resulted in incorrect parsing of `WPS` requests parameters).
* Actually fetch required `JSON` parameter from the request body if ``Content-Type`` is ``application/json``.
* Convert ``Permission`` enum to string for proper ACL comparison in ``MagpieOWSSecurity``.
* Fix ``raise_log`` function to allow proper evaluation against ``Exception`` type instead of ``message`` property.

0.10.0 (2019-04-15)
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Refactoring of literal strings to corresponding ``Permission`` enum (#167).
* Change all incorrect usages of ``HTTPNotAcceptable [406]`` to ``HTTPBadRequest [400]`` (#163).
* Add ``Accept`` header type checking before requests and return ``HTTPNotAcceptable [406]`` if invalid.
* Code formatting changes for consistency and cleanup of redundant/misguiding names (#162).
* Add option ``MAGPIE_UI_ENABLED`` allowing to completely disable all ``/ui`` route (enabled by default).
* Add more unittests (#74).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix swagger responses status code and description and fix erroneous body (#126).
* Fix invalid member count value returned on ``/groups/{id}`` request.
* Fix invalid ``DELETE /users/{usr}/services/{svc}/permissions/{perm}`` request not working.

0.9.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Greatly reduce docker image size.
* Allow quick functional testing using sequences of local app form submissions.
* Add test methods for UI redirects to other views from button click in displayed page.
* Change resource response for generic ``resource: {<info>}`` instead of ``{resource-id}: {<info>}``.
* Add permissions config to auto-generate user/group rules on startup.
* Attempt db creation on first migration if not existing.
* Add continuous integration testing and deployment (with python 2/3 tests).
* Ensure python compatibility for Python 2.7, 3.5, 3.6 (via `Travis-CI`).
* Reduce excessive ``sqlalchemy`` logging using ``MAGPIE_LOG_LEVEL >= INFO``.
* Use schema API route definitions for UI calls.
* Use sub-requests API call for UI operations (fixes issue `#114 <https://github.com/Ouranosinc/Magpie/issues/114>`_).
* Add new route ``/services/types`` to obtain a list of available service types.
* Add ``resource_child_allowed`` and ``resource_types_allowed`` fields in service response.
* Change service response for generic ``service: {<info>}`` instead of ``{service-name}: {<info>}``.
* Add new route ``/services/types/{svc_type}/resources`` for details about child service type resources.
* Error handling of reserved route keywords service `types` and current user ``MAGPIE_LOGGED_USER``.
* Additional tests for new routes and operations previously left unevaluated.
* Logging requests and exceptions according to `MAGPIE_LOG_REQUEST` and `MAGPIE_LOG_EXCEPTION` values.
* Better handling of ``HTTPUnauthorized [401]`` and ``HTTPForbidden [403]`` according to unauthorized view
  (invalid access token/headers or forbidden operation under view).
* Better handling of ``HTTPNotFound [404]`` and ``HTTPMethodNotAllowed [405]`` on invalid routes and request methods.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix UI add child button broken by introduced ``int`` resource id type checking.
* Fix `Travis-CI` test suite execution and enable PEP8 lint checks.
* Fix yaml security issue using updated package distribution.
* Fix invalid conflict service name check on service update request.
* Fix many invalid or erroneous swagger specifications.

0.8.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update `MagpieAdapter` to match process store changes.
* Provide user ID on API routes returning user info.

0.7.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add service resource auto-sync feature.
* Return user/group services if any sub-resource has permissions.
* Add inherited resource permission with querystring (deprecate `inherited_<>` routes warnings).
* Add flag to return `effective` permissions from user resource permissions requests.
* hide service private URL on non administrator level requests.
* Make cookies expire-able by setting ``MAGPIE_COOKIE_EXPIRE`` and provide cookie only on http
  (`JS CSRF` attack protection).
* Update ``MagpieAdapter.MagpieOWSSecurity`` for `WSO2` seamless integration with Authentication header token.
* Update ``MagpieAdapter.MagpieProcess`` for automatic handling of REST-API WPS process route access permissions.
* Update ``MagpieAdapter.MagpieService`` accordingly to inherited resources and service URL changes.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fixes related to postgres DB entry conflicting inserts and validations.
* Fix external providers login support (validated for `DKRZ`, `GitHub` and `WSO2`).

0.6.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``/magpie/api/`` route to locally display the Magpie REST API documentation.
* Move many source files around to regroup by API/UI functionality.
* Auto-generation of swagger REST API documentation.
* Unit tests.
* Validation of permitted resource types children under specific parent service or resource.
* ``ServiceAPI`` to filter ``read``/``write`` of specific HTTP methods on route parts.
* ``ServiceAccess`` to filter top-level route ``access`` permission of a generic service URL.
* Properly return values of field ``permission_names`` under ``/services/.*`` routes.
* Update make procedures and postgres variables specific to magpie.

0.5.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Independent user/group permissions, no more 'personal' group to reflect user permissions.
* Service specific resources with service*-typed* Resource permissions.
* More verification of resources permissions under specific services.
* Reference to root service from each sub-resource.
* Inheritance of user and group permissions with different routes.
* Improve some routes returned codes, inputs check, and requests formats (JSON).

0.4.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Default admin permissions.
* Block UI view permissions of all pages if not logged in.
* Signout clear header to forget user.
* Push to Phoenix adjustments and new push button option.

0.3.x
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add `ncWMS` support for `getmap`, `getcapabilities`, `getmetadata` on ``thredds`` resource.
* Add `ncWMS2` to default providers.
* Add `geoserverwms` service.
* Remove load balanced `Malleefowl` and `Catalog`.
* Push service provider updates to `Phoenix` on service edit or initial setup with `getcapabilities` for `anonymous`.
* Major update of `Magpie REST API 0.2.x documentation` to match returned codes/messages from 0.2.0 changes.
* Normalise additional HTTP request responses omitted from 0.2.0 (404, 500, and other missed responses).
* Remove internal api call, separate login external from local, direct access to `ziggurat` login.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix UI ``"Magpie Administration"`` to redirect toward home page instead of `PAVICS` platform.
* Fix bug during user creation against preemptive checks.
* Fix issues from `0.2.x` versions.

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
