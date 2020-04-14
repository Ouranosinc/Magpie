========
Usage
========

Package
~~~~~~~

To use Magpie in a project, fist you need to install it. To do so, you can do a basic ``pip install``.
For more details or other installation variants and preparation, see `installation`_ and
`configuration`_ procedures.

Then simply import the Python package::

    import magpie


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

Helpers
~~~~~~~

Multiple CLI `helpers`_ are provided. These consist mostly of setup operation scripts that are
automatically executed during `Magpie` startup. Additional common functions are also provided such as registering
service providers from a configuration file or creating basic user accounts. Please refer to their corresponding usage
by calling them with ``--help`` argument for more details.

.. _helpers: https://github.com/Ouranosinc/Magpie/tree/master/magpie/helpers
.. _configuration: configuration
.. _installation: installation
