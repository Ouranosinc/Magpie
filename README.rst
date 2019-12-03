======================================
Magpie: A RestFul AuthN/AuthZ service
======================================
Magpie (the smart-bird)
  *a very smart bird who knows everything about you.*

Magpie is service for AuthN/AuthZ accessible via a `RestAPI`_ implemented with the Pyramid web framework.
It allows you to manage User/Group/Resource/Permission with a postgres database.
Behind the scene, it uses `Ziggurat-Foundations`_ and `Authomatic`_.


.. start-badges

.. list-table::
    :stub-columns: 1

    * - dependencies
      - | |py_ver| |requires|
    * - build status
      - | |travis_latest| |travis_tagged| |readthedocs| |coverage| |codacy|
    * - docker status
      - | |docker_build_mode| |docker_build_status|
    * - releases
      - | |version| |commits-since|

.. |py_ver| image:: https://img.shields.io/badge/python-2.7%2C%203.5%2B-blue.svg
    :alt: Requires Python 2.7, 3.5+
    :target: https://www.python.org/getit

.. |commits-since| image:: https://img.shields.io/github/commits-since/Ouranosinc/Magpie/1.7.4.svg
    :alt: Commits since latest release
    :target: https://github.com/Ouranosinc/Magpie/compare/1.7.4...master

.. |version| image:: https://img.shields.io/badge/tag-1.7.4-blue.svg?style=flat
    :alt: Latest Tag
    :target: https://github.com/Ouranosinc/Magpie/tree/1.7.4

.. |requires| image:: https://requires.io/github/Ouranosinc/Magpie/requirements.svg?branch=master
    :alt: Requirements Status
    :target: https://requires.io/github/Ouranosinc/Magpie/requirements/?branch=master

.. |travis_latest| image:: https://img.shields.io/travis/com/Ouranosinc/Magpie/master.svg?label=master
    :alt: Travis-CI Build Status (master branch)
    :target: https://travis-ci.com/Ouranosinc/Magpie

.. |travis_tagged| image:: https://img.shields.io/travis/com/Ouranosinc/Magpie/1.7.4.svg?label=1.7.4
    :alt: Travis-CI Build Status (latest tag)
    :target: https://github.com/Ouranosinc/Magpie/tree/1.7.4

.. |readthedocs| image:: https://img.shields.io/readthedocs/pavics-magpie
    :alt: Readthedocs Build Status (master branch)
    :target: `readthedocs`_

.. |coverage| image:: https://img.shields.io/codecov/c/gh/Ouranosinc/Magpie.svg?label=coverage
    :alt: Travis-CI CodeCov Coverage
    :target: https://codecov.io/gh/Ouranosinc/Magpie

.. |codacy| image:: https://api.codacy.com/project/badge/Grade/1920f28c7e2140a083f527a803c58ae7
    :alt: Codacy Badge
    :target: https://www.codacy.com/app/fmigneault/Magpie?utm_source=github.com&utm_medium=referral&utm_content=Ouranosinc/Magpie&utm_campaign=Badge_Grade

.. |docker_build_mode| image:: https://img.shields.io/docker/automated/pavics/magpie.svg?label=build
    :alt: Docker Build Status (latest tag)
    :target: https://hub.docker.com/r/pavics/magpie/builds

.. |docker_build_status| image:: https://img.shields.io/docker/build/pavics/magpie.svg?label=status
    :alt: Docker Build Status (latest tag)
    :target: https://hub.docker.com/r/pavics/magpie/builds

.. end-badges


Documentation
=============

The REST API documentation is auto-generated and served under ``{MAGPIE_URL}/api/`` using Swagger-UI with tag ``latest``.

More ample details about installation, configuration and usage are provided on `readthedocs`_.
These are generated from corresponding information provided in `docs`_.

.. _readthedocs: https://pavics-magpie.readthedocs.io
.. _docs: ./docs

Configuration
=============

| Multiple configuration options exist for ``Magpie`` application.
| Please refer to `configuration`_ for details.

.. _configuration: ./docs/configuration.rst


Usage
=====

See `usage`_ for details.

.. _usage: ./docs/usage.rst

Change History
==============

Addressed features, changes and bug fixes per version tag are available in `HISTORY`_.

.. _HISTORY: ./HISTORY.rst

Docker Images
=============

Following most recent variants are available:

.. |br| raw:: html

    <br>

.. list-table::
    :header-rows: 1

    * - Magpie
      - Twitcher |br|
        (with integrated ``MagpieAdapter``)
    * - pavics/magpie:1.7.4
      - pavics/twitcher:magpie-1.7.4
    * - pavics/magpie:latest
      - pavics/twitcher:magpie-latest


**Notes:**

- Older tags the are also available: `Magpie Docker Images`_
- `Twitcher`_ image with integrated ``MagpieAdapter`` are only available for Magpie ``>=1.0.0``


.. _RestAPI: https://swaggerhub.com/apis/CRIM/magpie-rest-api
.. _Authomatic: https://authomatic.github.io/authomatic/
.. _Ziggurat-Foundations: https://github.com/ergo/ziggurat_foundations
.. _Magpie Docker Images: https://hub.docker.com/r/pavics/magpie/tags
.. _Twitcher: https://github.com/bird-house/twitcher
