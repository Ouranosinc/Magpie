.. :changelog:

History
=======

0.3.0
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


.. _magpie_api_tagged: https://app.swaggerhub.com/apis/fderue/magpie-rest_api
.. _magpie_api_0.1.0: https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.1.0
.. _magpie_api_0.1.1: https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.1.1
.. _magpie_api_0.2.0: https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.2.0
.. _magpie_api_0.2.x: https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.2.x
.. _magpie_api_0.3.x: https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.3.x
.. _Magpie REST API 0.1.0 documentation: magpie_api_0.1.0_
.. _Magpie REST API 0.1.1 documentation: magpie_api_0.1.1_
.. _Magpie REST API 0.2.0 documentation: magpie_api_0.2.0_
.. _Magpie REST API 0.2.x documentation: magpie_api_0.2.x_
.. _Magpie REST API 0.3.x documentation: magpie_api_0.3.x_
