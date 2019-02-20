======================================
Magpie: A RestFul AuthN/AuthZ service
======================================
Magpie (the smart-bird)
  *a very smart bird who knows everything about you.*

Magpie is service for AuthN/AuthZ accessible via a `RestAPI`_ implemented with the Pyramid web framework.
It allows you to manage User/Group/Resource/permission with a postgres database.
Behind the scene, it uses `Ziggurat-Foundations`_ and `Authomatic`_.


.. start-badges

.. list-table::
    :stub-columns: 1

    * - dependencies
      - | |py_ver| |requires|
    * - build status
      - | |travis_latest| |travis_tag| |coverage|
    * - docker status
      - | |docker_build_mode| |docker_build_status|
    * - releases
      - | |version| |commits-since|

.. |py_ver| image:: https://img.shields.io/badge/python-2.7%2C%203.5%2B-blue.svg
    :alt: Requires Python 2.7, 3.5+
    :target: https://www.python.org/getit

.. |commits-since| image:: https://img.shields.io/github/commits-since/Ouranosinc/Magpie/0.9.4.svg
    :alt: Commits since latest release
    :target: https://github.com/Ouranosinc/Magpie/compare/v0.9.4...master

.. |version| image:: https://img.shields.io/github/tag/ouranosinc/magpie.svg?style=flat
    :alt: Latest Tag
    :target: https://github.com/Ouranosinc/Magpie/tree/0.9.4

.. |requires| image:: https://requires.io/github/Ouranosinc/Magpie/requirements.svg?branch=master
    :alt: Requirements Status
    :target: https://requires.io/github/Ouranosinc/Magpie/requirements/?branch=master

.. |travis_latest| image:: https://img.shields.io/travis/com/Ouranosinc/Magpie/master.svg?label=master
    :alt: Travis-CI Build Status (master branch)
    :target: https://travis-ci.com/Ouranosinc/Magpie

.. |travis_tag| image:: https://img.shields.io/travis/com/Ouranosinc/Magpie/0.9.4.svg?label=0.9.4
    :alt: Travis-CI Build Status (latest tag)
    :target: https://github.com/Ouranosinc/Magpie/tree/0.9.4

.. |coverage| image:: https://img.shields.io/codecov/c/gh/Ouranosinc/Magpie.svg?label=coverage
    :alt: Travis-CI CodeCov Coverage
    :target: https://codecov.io/gh/Ouranosinc/Magpie

.. |docker_build_mode| image:: https://img.shields.io/docker/automated/pavics/magpie.svg?label=build
    :alt: Docker Build Status (latest tag)
    :target: https://hub.docker.com/r/pavics/magpie/builds

.. |docker_build_status| image:: https://img.shields.io/docker/build/pavics/magpie.svg?label=status
    :alt: Docker Build Status (latest tag)
    :target: https://hub.docker.com/r/pavics/magpie/builds

.. end-badges


REST API Documentation
======================

The documentation is auto-generated and served under `{HOSTNAME}/api/` using Swagger-UI with tag `latest`.
For convenience, older API versions are also provided.


Build package
=============

At the command line::

    $ conda create -n magpie
    $ source activate magpie
    $ make install


Installation
============

At the command line::

    $ pip install magpie


.. _RestAPI: https://swaggerhub.com/apis/CRIM/magpie-rest-api
.. _Authomatic: https://authomatic.github.io/authomatic/
.. _Ziggurat-Foundations: https://github.com/ergo/ziggurat_foundations

