.. usage_link:

========
Usage
========

Package
~~~~~~~

To use `Magpie` in a project, first you need to install it. To do so, you can do a basic ``pip install``.
For more details or other installation variants and environment preparation, see `installation`_ and
`configuration`_ procedures.

After this, you should be able to import the Python package to validate it is installed properly using::

    import magpie


Web Application
~~~~~~~~~~~~~~~~~~~~~

In most situation, you will want to run `Magpie` as a Web Application in combination with some Web Proxy
(e.g.: `Twitcher`_) that can interrogate `Magpie` about applicable user authentication and permission authorization
from the HTTP request session. To start the application, you can simply run the following command::

    make start

This will first install any missing dependencies in the current environment (see `installation`_), and will after start
a basic Web Application on ``localhost:2001`` with default configurations. Please note that you **MUST** have a
`PostgreSQL`_ database connection configured prior to running `Magpie` for it to operate (refer to `Configuration`_
for details).

For running the application, multiple
`WSGI HTTP Servers` can be employed (e.g.: `Gunicorn`_, `Waitress`_, etc.). They usually all support as input an INI
configuration file for specific settings. `Magpie` also employs such INI file to customize its behaviour.
See `Configuration`_ for further details, and please refer to the employed `WSGI` application documentation of your
liking for their respective setup requirements.

.. _Gunicorn: https://gunicorn.org/
.. _PostgreSQL: https://www.postgresql.org/
.. _Twitcher: https://github.com/bird-house/twitcher
.. _Waitress: https://github.com/Pylons/waitress

API
~~~~~~~

When the application is started, the Swagger API should be available under ``/api`` path. Please refer to this
documentation to discover all provided API paths and operations supported by `Magpie`. The API allows an administrator
with sufficient access rights to modify services, resources, users and groups references via HTTP requests.

GUI
~~~~~~~

When the application is started, `Magpie`'s UI should be directly accessible on the top endpoint path. This interface
allows quicker editing of elements accessible through the API by providing common operations such as modifying service
fields or adjusting specific user-resource permissions. To have access to this interface, the user must have
administrator permissions.

Additional Utilities
~~~~~~~~~~~~~~~~~~~~

Multiple `utilities`_ are provided either directly within `Magpie` as a package or through external resources.
Please refer to this section for more details.

.. _configuration: configuration.rst
.. _installation: installation.rst
.. _utilities: utilities.rst
