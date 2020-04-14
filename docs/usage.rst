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

Additional Utilities
~~~~~~~~~~~~~~~~~~~~

Multiple `utilities`_ are provided either directly within `Magpie` or through external resources.
Please refer to this section for more details.

.. _configuration: configuration.rst
.. _installation: installation.rst
.. _utilities: utilities.rst
