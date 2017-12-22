.. :changelog:

History
=======

[0.3.0][magpie-api-0.3.x]
---------------------

* ncWMS support for getmap, getcapabilities, getmetadata on thredds resource
* ncWMS2 added to default providers
* add geoserverwms
* remove load balanced mallefowl and catalog
* push service provider updates to phoenix on service modification or initial setup with getcapabilities for anonymous
* major update of [Magpie Rest API documentation][magpie-api-0.2.x] to match returned codes/messages from 0.2.0 changes
* normalise additional HTTP request responses omitted from 0.2.0 (404, 500, and other missed responses)
* remove internal api call, separate login external from local, direct access to ziggurat login
* fixes UI "Magpie Administration" to redirect toward home page instead of PAVICS platform
* fix bug during user creation against preemptive checks
* bug fixes from 0.2.x series

[0.2.0][magpie-api-0.2.0]
---------------------

* Revamp HTTP standard error output format, messages, values and general error/exception handling.
* Update [Magpie Rest API documentation][magpie-api-tagged]

[0.1.1][magpie-api-0.1.1]
---------------------

* Add edition of service URL via PUT/{service_name}.

[0.1.0][magpie-api-0.1.0]
---------------------

* First structured release.


[magpie-api-tagged](https://app.swaggerhub.com/apis/fderue/magpie-rest_api)
[magpie-api-0.1.0](https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.1.0)
[magpie-api-0.1.1](https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.1.1)
[magpie-api-0.2.0](https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.2.0)
[magpie-api-0.2.x](https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.2.x)
[magpie-api-0.3.x](https://app.swaggerhub.com/apis/fderue/magpie-rest_api/0.3.x)
