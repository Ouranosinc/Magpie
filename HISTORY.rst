.. :changelog:

History
=======

Unreleased
---------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* provide some documentation about ``magpie.constants`` module behaviour.
* remove some inspection comments by using combined requirements files.
* add constant ``MAGPIE_LOG_PRINT`` (default: ``False``) to enforce printing logs to console
  (equivalent to specifying a ``sys.stdout/stderr StreamHandler`` in ``magpie.ini``, but is not enforced anymore)
* update logging config to avoid duplicate outputs and adjust code to respect specified config.

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
* fix travis-ci test suite execution and enable PEP8 lint checks
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

`Magpie REST API latest documentation`_

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

`Magpie REST API 0.6.x documentation`_

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

`Magpie REST API 0.5.x documentation`_

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

`Magpie REST API 0.4.x documentation`_

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* default admin permissions
* block UI view permissions of all pages if not logged in
* signout clear header to forget user
* push to Phoenix adjustments and new push button option

0.3.x
---------------------

`Magpie REST API 0.3.x documentation`_

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* `ncWMS` support for `getmap`, `getcapabilities`, `getmetadata` on ``thredds`` resource
* `ncWMS2` added to default providers
* add `geoserverwms` service
* remove load balanced `Malleefowl` and `Catalog`
* push service provider updates to `Phoenix` on service edit or initial setup with `getcapabilities` for `anonymous`
* major update of `Magpie REST API 0.2.x documentation`_ to match returned codes/messages from 0.2.0 changes
* normalise additional HTTP request responses omitted from 0.2.0 (404, 500, and other missed responses)
* remove internal api call, separate login external from local, direct access to `ziggurat` login

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* fix UI ``"Magpie Administration"`` to redirect toward home page instead of `PAVICS` platform
* fix bug during user creation against preemptive checks
* fix issues from `0.2.x` versions

0.2.0
---------------------

`Magpie REST API 0.2.0 documentation`_

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Revamp HTTP standard error output format, messages, values and general error/exception handling.
* Update `Magpie REST API 0.2.0 documentation`_

0.1.1
---------------------

`Magpie REST API 0.1.1 documentation`_

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add edition of service URL via ``PUT /{service_name}``.

0.1.0
---------------------

`Magpie REST API 0.1.0 documentation`_

* First structured release.


.. _magpie_api_latest: https://colibri.crim.ca/magpie/api/?urls.primaryName=latest
.. _magpie_api_0.1.0: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.1.0
.. _magpie_api_0.1.1: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.1.1
.. _magpie_api_0.2.0: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.2.0
.. _magpie_api_0.2.x: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.2.x
.. _magpie_api_0.3.x: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.3.x
.. _magpie_api_0.4.x: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.4.x
.. _magpie_api_0.5.x: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.5.x
.. _magpie_api_0.6.x: https://colibri.crim.ca/magpie/api/?urls.primaryName=0.6.x
.. _Magpie REST API 0.1.0 documentation: magpie_api_0.1.0_
.. _Magpie REST API 0.1.1 documentation: magpie_api_0.1.1_
.. _Magpie REST API 0.2.0 documentation: magpie_api_0.2.0_
.. _Magpie REST API 0.2.x documentation: magpie_api_0.2.x_
.. _Magpie REST API 0.3.x documentation: magpie_api_0.3.x_
.. _Magpie REST API 0.4.x documentation: magpie_api_0.4.x_
.. _Magpie REST API 0.5.x documentation: magpie_api_0.5.x_
.. _Magpie REST API 0.6.x documentation: magpie_api_0.6.x_
.. _Magpie REST API latest documentation: _magpie_api_latest
