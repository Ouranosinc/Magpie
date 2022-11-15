.. explicit references must be used in this file (not references.rst) to ensure they are directly rendered on Github

======================================
Magpie: A RestFul AuthN/AuthZ service
======================================
Magpie (the smart-bird)
  *a very smart bird who knows everything about you.*

Magpie is service for AuthN/AuthZ accessible via a `REST API`_ implemented with the `Pyramid`_ web framework.
It allows you to manage User/Group/Service/Resource/Permission with a `PostgreSQL`_ database.
Behind the scene, it uses `Ziggurat-Foundations`_ and `Authomatic`_.


.. start-badges

.. list-table::
    :header-rows: 0
    :stub-columns: 1
    :widths: 10,90

    * - dependencies
      - | |py_ver_support| |py_ver_recommend| |dependencies|
    * - tests status
      - | |github_latest| |github_tagged| |coverage| |codacy|
    * - docker status
      - | |docker_build_mode| |docker_build_status| |docker_latest_tag| |docker_semver_tag|
    * - releases
      - | |version| |commits-since|

.. |py_ver_support| image:: https://img.shields.io/badge/python%20%28legacy%20support%29-2.7%2C%203.5%2B-orange.svg
    :alt: Python 2.7, 3.5+ supported (legacy)
    :target: https://www.python.org/getit

.. |py_ver_recommend| image:: https://img.shields.io/badge/python%20%28recommended%29-3.7%2B-blue.svg
    :alt: Python 3.7+ recommended
    :target: https://www.python.org/getit

.. |commits-since| image:: https://img.shields.io/github/commits-since/Ouranosinc/Magpie/3.27.0.svg
    :alt: Commits since latest release
    :target: https://github.com/Ouranosinc/Magpie/compare/3.27.0...master

.. |version| image:: https://img.shields.io/badge/tag-3.27.0-blue.svg?style=flat
    :alt: Latest Tag
    :target: https://github.com/Ouranosinc/Magpie/tree/3.27.0

.. |dependencies| image:: https://pyup.io/repos/github/Ouranosinc/Magpie/shield.svg
    :alt: Dependencies Status
    :target: https://pyup.io/account/repos/github/Ouranosinc/Magpie/

.. |github_latest| image:: https://img.shields.io/github/workflow/status/Ouranosinc/Magpie/Tests/master?label=master
    :alt: Github Actions CI Build Status (master branch)
    :target: https://github.com/Ouranosinc/Magpie/actions?query=workflow%3ATests+branch%3Amaster

.. |github_tagged| image:: https://img.shields.io/github/workflow/status/Ouranosinc/Magpie/Tests/3.27.0?label=3.27.0
    :alt: Github Actions CI Build Status (latest tag)
    :target: https://github.com/Ouranosinc/Magpie/actions?query=workflow%3ATests+branch%3A3.27.0

.. |readthedocs| image:: https://img.shields.io/readthedocs/pavics-magpie
    :alt: Readthedocs Build Status (master branch)
    :target: `readthedocs`_

.. |coverage| image:: https://img.shields.io/codecov/c/gh/Ouranosinc/Magpie.svg?label=coverage
    :alt: Travis-CI CodeCov Coverage
    :target: https://codecov.io/gh/Ouranosinc/Magpie

.. |codacy| image:: https://app.codacy.com/project/badge/Grade/0dd500de5e3c4bdf84093eaa64cf9a81
    :alt: Codacy Badge
    :target: https://app.codacy.com/gh/Ouranosinc/Magpie/dashboard

.. |docker_build_mode| image:: https://img.shields.io/docker/automated/pavics/magpie.svg?label=build
    :alt: Docker Build Status (latest tag)
    :target: https://hub.docker.com/r/pavics/magpie/builds

.. |docker_build_status| image:: https://img.shields.io/docker/cloud/build/pavics/magpie.svg?label=status
    :alt: Docker Build Status (latest tag)
    :target: https://hub.docker.com/r/pavics/magpie/builds

.. |docker_latest_tag| image:: https://img.shields.io/docker/v/pavics/magpie?label=last%20build
    :alt: Docker Latest Tag
    :target: https://hub.docker.com/r/pavics/magpie/tags?page=1&ordering=last_updated&name=latest

.. |docker_semver_tag| image:: https://img.shields.io/docker/v/pavics/magpie?label=version&sort=semver
    :alt: Docker Version Tag
    :target: https://hub.docker.com/r/pavics/magpie/tags?page=1&ordering=last_updated&name=3.27.0

.. end-badges

--------------
Documentation
--------------

The REST API documentation is auto-generated and served under ``{MAGPIE_URL}/api/`` using Swagger-UI with tag
``latest``.

| More ample details about installation, configuration and usage are provided on |readme_readthedocs|_.
| These are generated from corresponding information provided in |github_docs|_ directory.

----------------------------
Configuration and Usage
----------------------------

| Multiple configuration options exist for ``Magpie`` application.
| Please refer to |readme_configuration|_ section for details.
| See |readme_usage|_ section for details.

--------------
Change History
--------------

Addressed features, changes and bug fixes per version tag are available in |readme_changes|_.

--------------
Docker Images
--------------

Following most recent variants are available:

.. |br| raw:: html

    <br>

.. list-table::
    :header-rows: 1

    * - Magpie
      - Twitcher |br|
        (with integrated ``MagpieAdapter``)
    * - ``pavics/magpie:3.27.0``
      - ``pavics/twitcher:magpie-3.27.0``
    * - ``pavics/magpie:latest``
      - ``pavics/twitcher:magpie-latest``


**Notes:**

- Older tags the are also available: `Magpie Docker Images`_
- `Twitcher`_ image with integrated ``MagpieAdapter`` are only available for Magpie ``>=1.0.0``

.. these reference must be left direct (not included with 'docs/references.rst') to allow pretty rendering on Github
.. |readme_changes| replace:: CHANGES
.. _readme_changes: CHANGES.rst
.. |readme_configuration| replace:: Configuration
.. _readme_configuration: docs/configuration.rst
.. |readme_usage| replace:: Usage
.. _readme_usage: docs/usage.rst
.. |readme_readthedocs| replace:: ReadTheDocs
.. _readme_readthedocs: https://pavics-magpie.readthedocs.io
.. |github_docs| replace:: docs
.. _github_docs: https://github.com/Ouranosinc/Magpie/tree/master/docs

.. REST API redoc reference is auto-generated by sphinx from magpie cornice-swagger definitions
.. _REST API: https://pavics-magpie.readthedocs.io/en/latest/api.html
.. _Authomatic: https://authomatic.github.io/authomatic/
.. _PostgreSQL: https://www.postgresql.org/
.. _Pyramid: https://docs.pylonsproject.org/projects/pyramid/
.. _Ziggurat-Foundations: https://github.com/ergo/ziggurat_foundations
.. _Magpie Docker Images: https://hub.docker.com/r/pavics/magpie/tags
.. _Twitcher: https://github.com/bird-house/twitcher
