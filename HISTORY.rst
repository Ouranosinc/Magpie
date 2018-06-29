.. :changelog:

History
=======

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
* remove load balanced mallefowl and catalog
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
