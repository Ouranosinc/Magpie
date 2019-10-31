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
      - | |travis_latest| |travis_tag| |coverage| |codacy|
    * - docker status
      - | |docker_build_mode| |docker_build_status|
    * - releases
      - | |version| |commits-since|

.. |py_ver| image:: https://img.shields.io/badge/python-2.7%2C%203.5%2B-blue.svg
    :alt: Requires Python 2.7, 3.5+
    :target: https://www.python.org/getit

.. |commits-since| image:: https://img.shields.io/github/commits-since/Ouranosinc/Magpie/1.6.3.svg
    :alt: Commits since latest release
    :target: https://github.com/Ouranosinc/Magpie/compare/1.6.3...master

.. |version| image:: https://img.shields.io/badge/tag-1.6.3-blue.svg?style=flat
    :alt: Latest Tag
    :target: https://github.com/Ouranosinc/Magpie/tree/1.6.3

.. |requires| image:: https://requires.io/github/Ouranosinc/Magpie/requirements.svg?branch=master
    :alt: Requirements Status
    :target: https://requires.io/github/Ouranosinc/Magpie/requirements/?branch=master

.. |travis_latest| image:: https://img.shields.io/travis/com/Ouranosinc/Magpie/master.svg?label=master
    :alt: Travis-CI Build Status (master branch)
    :target: https://travis-ci.com/Ouranosinc/Magpie

.. |travis_tag| image:: https://img.shields.io/travis/com/Ouranosinc/Magpie/1.6.3.svg?label=1.6.3
    :alt: Travis-CI Build Status (latest tag)
    :target: https://github.com/Ouranosinc/Magpie/tree/1.6.3

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


REST API Documentation
======================

The documentation is auto-generated and served under ``{HOSTNAME}/api/`` using Swagger-UI with tag ``latest``.


Build package
=============

At the command line::

    conda create -n magpie
    source activate magpie
    make install


Installation
============

At the command line::

    pip install magpie


Configuration
=============

| Multiple configuration options exist for ``Magpie`` application.
| Please refer to `<CONFIGURATION.rst>`_ for details.

Change History
==============

Addressed features, changes and bug fixes per version tag are available in `<HISTORY.rst>`_.

Helpers
==============

Multiple CLI *helpers* are provided in `<magpie/helpers>`_. These consist mostly of setup operation scripts that are
automatically executed during ``Magpie`` startup. Additional common functions are also provided such as registering
service providers from a configuration file or creating basic user accounts. Please refer to their corresponding usage
by calling them with ``--help`` argument for more details.

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
    * - pavics/magpie:1.6.3
      - pavics/twitcher:magpie-1.6.3
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
