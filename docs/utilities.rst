Utilities
============

.. utilities_helpers:

Magpie CLI Helpers
---------------------

Multiple CLI helpers are provided. These consist mostly of setup operation scripts that are automatically executed
during `Magpie` startup. Additional common functions are also provided such as registering service providers from a
configuration file or creating basic user accounts. Please refer to their corresponding usage by calling them with
``--help`` argument for more details.

Available helpers:

- ``create_users``
- ``register_default_users``
- ``register_providers``
- ``run_database_migration``
- ``sync_resources``

Source code of these helpers can be found `here <https://github.com/Ouranosinc/Magpie/tree/master/magpie/helpers>`_.

.. utilities_connection:

Magpie Connection
---------------------

The repository `Ouranosinc/requests-magpie`_ offers basic Authentication connection to a running `Magpie` instance
similarly to how traditional ``HTTPBasicAuth`` works under the hood. Using this, you can easily plug-and-play `Magpie`
in order to use it with the standard ``requests`` library by passing ``auth=MagpieAuth(<...>)``.

.. _Ouranosinc/requests-magpie: https://github.com/Ouranosinc/requests-magpie
