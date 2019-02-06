.. :changelog:

History
=======

0.9.x
---------------------

* add permissions config to auto-generate user/group rules on startup
* fix many invalid or erroneous swagger specifications
* attempt db creation on first migration if not existing
* add continuous integration testing and deployment (with python 2/3 tests)
* ensure python compatibility for Python 2.7, 3.5, 3.6
* reduce excessive sqlalchemy logging using `MAGPIE_LOG_LEVEL >= INFO`
* use schema API route definitions for UI calls
* use sub-requests API call for UI operations (fixes issue #114)
* add new route `/services/types` to obtain a list of available service types
* add `resource_child_allowed` and `resource_types_allowed` fields in service response
* change service response for generic `service: {<info>}` instead of `{service-name}: {<info>}`
* add new route `/services/types/{svc_type}/resources` for details about child service type resources
* additional tests for new routes and operations previously left unevaluated

0.8.x
---------------------

* update MagpieAdapter to match process store changes
* provide user ID on API routes returning user info

0.7.x
---------------------

`Magpie REST API latest documentation`_

* add service resource auto-sync feature
* return user/group services if any sub-resource has permissions
* add inherited resource permission with querystring (deprecate `inherited_<>` routes warnings)
* add flag to return `effective` permissions from user resource permissions requests
* hide service private URL on non administrator level requests
* fix external providers login support (validated for DKRZ, GitHub and WSO2)
* make cookies expire-able by setting `MAGPIE_COOKIE_EXPIRE` and provide cookie only on http (JS CSRF attack protection)
* update `MagpieAdapter.MagpieOWSSecurity` for WSO2 seamless integration with Authentication header token
* update `MagpieAdapter.MagpieProcess` for automatic handling of REST-API WPS process route access permissions
* update `MagpieAdapter.MagpieService` accordingly to inherited resources and service URL changes
* bug fixes related to postgres DB entry conflicting inserts and validations

0.6.x
---------------------

`Magpie REST API 0.6.x documentation`_

* add `/magpie/api/` route to locally display the Magpie REST API documentation
* move many source files around to regroup by API/UI functionality
* auto-generation of swagger REST API documentation
* unit tests
* validation of permitted resource types children under specific parent service or resource
* ServiceAPI to filter read/write of specific GET,POST,etc on route parts
* ServiceAccess to filter top-level route 'access' permission of a generic service URL
* properly return values of field `permission_names` under `/services/.*` routes
* update make procedures and postgres variables specific to magpie

0.5.x
---------------------

`Magpie REST API 0.5.x documentation`_

* independent user/group permissions, no more 'personal' group to reflect user permissions
* service specific resources with service*-typed* resource permissions
* more verification of resources permissions under specific services
* reference to root service from each sub-resource
* inheritance of user and group permissions with different routes
* improve some routes returned codes, inputs check, and requests formats (JSON)

0.4.x
---------------------

`Magpie REST API 0.4.x documentation`_

* default admin permissions
* block UI view permissions of all pages if not logged in
* signout clear header to forget user
* push to Phoenix adjustments and new push button option

0.3.x
---------------------

`Magpie REST API 0.3.x documentation`_

* ncWMS support for getmap, getcapabilities, getmetadata on thredds resource
* ncWMS2 added to default providers
* add geoserverwms
* remove load balanced Malleefowl and Catalog
* push service provider updates to phoenix on service modification or initial setup with getcapabilities for anonymous
* major update of `Magpie REST API 0.2.x documentation`_ to match returned codes/messages from 0.2.0 changes
* normalise additional HTTP request responses omitted from 0.2.0 (404, 500, and other missed responses)
* remove internal api call, separate login external from local, direct access to ziggurat login
* fixes UI "Magpie Administration" to redirect toward home page instead of PAVICS platform
* fix bug during user creation against preemptive checks
* bug fixes from 0.2.x series

0.2.0
---------------------

`Magpie REST API 0.2.0 documentation`_

* Revamp HTTP standard error output format, messages, values and general error/exception handling.
* Update `Magpie REST API 0.2.0 documentation`_

0.1.1
---------------------

`Magpie REST API 0.1.1 documentation`_

* Add edition of service URL via PUT/{service_name}.

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
