.. include:: references.rst
.. _usage:

========
Usage
========

Package
----------------------

To use `Magpie` in a project, first you need to install it. To do so, you can do a basic ``pip install``.
For more details or other installation variants and environment preparation, see :ref:`installation` and
:ref:`configuration` procedures.

After this, you should be able to import the Python package to validate it is installed properly using:

.. code-block:: python

    import magpie


.. _usage_webapp:

Web Application
----------------------

In most situation, you will want to run `Magpie` as a Web Application in combination with some Web Proxy
(e.g.: `Twitcher`_) that can interrogate `Magpie` about applicable user authentication and permission authorization
from the HTTP request session. To start the application, you can simply run the following command.

.. code-block:: console

    make start

This will first install any missing dependencies in the current environment (see :ref:`installation`), and will after
start a basic Web Application on ``localhost:2001`` with default configurations. Please note that you **MUST** have a
`PostgreSQL`_ database connection configured prior to running `Magpie` for it to operate (refer to :ref:`Configuration`
for details).

For running the application, multiple `WSGI HTTP Servers` can be employed (e.g.: `Gunicorn`_, `Waitress`_, etc.).
They usually all support as input an INI configuration file for specific settings. `Magpie` also employs such INI file
to customize its behaviour. See `Configuration`_ for further details, and please refer to the employed `WSGI`
application documentation of your liking for their respective setup requirements.


.. _usage_api:

API
----------------------

When the application is started, the Swagger API should be available under ``/api`` path. This will render the *current*
version API and applicable requests. Please refer to this documentation to discover all provided API paths and
operations supported by `Magpie` on a *running* instance (that could be older than latest code base). Alternatively,
documentation of *all* versions is available on `ReadTheDocs`_.

The API allows an administrator-level user to modify services, resources, users and groups references via HTTP requests.
To do these kind of operations, sufficient access rights must be provided to the corresponding user (either directly or
through administrative-level group membership).

Some API routes are accessible by *any*-level user access. These are designated by :term:`Logged User` in the
documentation. When accessing such API paths, the applicable user for which the request is accomplished uses contextual
information from authentication headers and/or cookies of the request. When no user is authenticated, a minimal subset
of paths will provide some publicly available details, such as current session user. Other routes will be more verbose
according to the applicable user permission (or is inherited group memberships).

.. versionchanged:: 2.0

    As of this version, some API paths will offer additional :term:`Logged User` operations such as self-registration
    to publicly available groups. See the appropriate API version documentation for routes that could be added or
    adjusted with this new functionality. Note also that a valid user account will still be required to access these
    routes.

Please refer to :ref:`permissions` for further details about applicable user access levels.

.. _usage_cli:

CLI
----------------------

After successful :ref:`installation` of `Magpie` package, multiple :ref:`cli_helpers` become available
as CLI applications callable from the shell. These can be quite useful to run typical `Magpie` operations targeting
a local or remote instance. Please refer to the relevant page for further details.

.. _configuration: configuration.rst
.. _installation: installation.rst
.. _permissions: permissions.rst
.. _utilities: utilities.rst

.. _usage_ui:

GUI
----------------------

When the application is started, `Magpie`'s UI should be directly accessible on the top endpoint path. This interface
allows quicker editing of elements accessible through the API by providing common operations such as modifying service
fields or adjusting specific user-resource permissions. To have access to this interface, the user must have
administrator permissions.

.. versionchanged:: 2.0

    User-scoped views such as logged-user account details are now accessible to non-administrator level users.
    These offer some basic functionalities such as registration to publicly visible groups. Users minimally require
    to be logged-in (successful :term:`Authentication`) in order to access these pages. The UI pages are accessible
    using the ``Account`` button from the main entrypoint of the `Magpie` UI.


.. _usage_docker:

Docker Application
-----------------------

Two `Docker` images are provided for very version released.

The first, simply named ``pavics/magpie``, is to execute `Magpie` itself as a :ref:`usage_webapp`.
This simultaneously offers both :ref:`usage_api` and :ref:`usage_ui` interfaces accessible from the configured endpoint.
Using the same image and an override of the ``CMD``, it is also possible to run any of the :ref:`usage_cli` operations
with all preinstalled package dependencies. This image's `Dockerfile`_ is a good reference to understand how to run the
:ref:`usage_webapp` locally if desired.

The second `Docker` image consists of `Twitcher`_ code base with integrated :class:`magpie.adapter.MagpieAdapter` such
that they can communicate between each other. Each tagged `Magpie` version will have an automatically deployed and
corresponding `Twitcher`_ image tag as ``pavics/twitcher:magpie-<version>``.

Usually, both images are employed in tandem with a `PostgreSQL`_ database connexion within a ``docker-compose.yml``
configuration, similar to the following example. It is recommended to keep the versions in sync to ensure their
interoperability. Both images must also share some configurations, such as but not limited to, the same
:envvar:`MAGPIE_SECRET` in order to resolve operations in the same manner. See :ref:`config_twitcher` for
further details.


.. code-block:: YAML

    magpie:
      image: pavics/magpie:<version>
      # ... other Magpie configs ...
      links:
        - postgres
      volumes:
        - <some-path>/magpie.ini:/opt/local/src/magpie/config/magpie.ini

    twitcher:
      image: pavics/twitcher:magpie-<version>
      # ... other Twitcher configs ...
      links:
        - postgres
      volumes:
        - <some-path>/twitcher.ini:/opt/birdhouse/src/twitcher/twitcher.ini

    postgres:
      image: postgres:9.6
      # ... other PostgreSQL configs ...
      environment:
        PGDATA: /var/lib/postgresql/data/pgdata
      volumes:
        - <data-persistence-dir>:/var/lib/postgresql/data/pgdata


.. _usage_tests:

Testing
----------------------

Basic Setup
~~~~~~~~~~~~~~~~~~~~~~

To execute the tests on your local machine, a `PostgreSQL`_ instance must be running.
This `PostgreSQL`_ instance can be easily initialized by using the `docker-compose.yml.example`_ file
with the default values. Make sure the values defined in ``postgres.env`` (custom copy of `postgres.env.example`_)
are also corresponding to your testing setup.

There are both `local` and `remote` tests. The `PostgreSQL`_ is sufficient for the `local` tests but the `remote` tests
also require a separately running instance of `Magpie`. Both suites are *almost* identical, but `local` ones are
slightly more in depth as they can evaluate complicated edge cases hard to validate with a remote instance. The `local`
tests should be your reference to see if new features are working and not breaking other functionalities. The `remote`
are intended to validate older or pre-deployed servers, although with slightly more limited coverage.

A basic `Magpie` instance can also be initialized by using the `docker-compose.yml.example`_ file.
Note that the environment variables :envvar:`MAGPIE_TEST_REMOTE_SERVER_URL` and :envvar:`HOST_FQDN`
must first be defined for the `remote` tests.
For example, these default values should work with ``docker-compose``:

.. code-block:: console

    export MAGPIE_TEST_REMOTE_SERVER_URL=http://localhost:2001
    export HOST_FQDN=localhost

To start the tests, you can simply run one of the following command:

.. code-block:: console

    make test
    make test-local
    make test-remote

.. note::
    Although targeted URL is ``localhost``, using :envvar:`MAGPIE_TEST_REMOTE_SERVER_URL` makes the test `remote`.
    A `Magpie` instance should be running with that served location (e.g.: using ``make start`` or ``docker-compose``).
    Running `local` tests will boot its own Web Applicable instance, but `PostgreSQL`_ must still be accessible.


Customizing Tests
~~~~~~~~~~~~~~~~~~~~~~

Specific tests can be enabled or disabled by *category*, using variables in ``magpie.env``
(copy of `magpie.env.example`_). Tests marked with the corresponding variables will be executed or not if they were
marked as matching that category. Alternatively, you can also provide the conditions directly using:

.. code-block:: console

    make test-custom SPEC="utils and local"
    make test-custom SPEC="not remote"
    # etc.

Value of ``SPEC`` follows standard ``pytest`` marker notations. Markers are mapped against the corresponding
``MAGPIE_TEST_<MARKER>`` variables in `magpie.env.example`_.

When developing new features that change an older behaviour, tests **MUST** be made conditional to older versions to
preserve functional `remote` tests. To do so, the principal method is to employ utility ``tests.utils.warn_version`` to
create a `safeguard` against execution of the test it is placed into. Tests can then be skipped if the targeted instance
does not fulfill version requirements specified with the `safeguard`.

Another approach is to employ ``if/else`` blocks to separate execution by version of the tested instance as follows:

.. code-block:: python

    if TestVersion(self.version) >= TestVersion("1.2.3"):
        # specific test for 1.2.3 and above
    else:
        # tests for an older instance


This allows fine-grained operation if the changes between versions are relatively "minor".

.. note::
    When developing new features, it often happens that the new version does not yet exist, since the feature is not
    yet merged, tagged and deployed. Any `safeguards` checking against this future version would then always ignore
    the new feature tests! To work around this, you should define variable ``MAGPIE_TEST_VERSION=latest`` in your
    environment (or any other loaded ``.env`` file). This will tell the `local` test runner to consider the current
    version as always greater that any compared minimal requirement, effectively enabling ``latest`` test changes.
