.. include:: references.rst
.. _utilities:

Utilities
============

.. _cli_helpers:
.. _utilities_helpers:

Magpie CLI Helpers
---------------------

Multiple CLI helpers are provided. These consist mostly of setup operation scripts that are automatically executed
during `Magpie` startup. Additional common functions are also provided such as registering service providers from a
configuration file or creating basic user accounts. Please refer to their corresponding usage by calling them with
``--help`` argument for more details.

Available helpers:

.. list-table::
    :header-rows: 1

    * - Command
      - Description
    * - ``magpie_batch_update_users``
      - Register or unregister users using entries provided by batch file or arguments.
    * - ``magpie_register_defaults``
      - | Register default users and groups for `Magpie` internal operation.
        | See :ref:`configuration` for details on applicable parameters definitions.
    * - ``magpie_register_providers``
      - | Register service providers from a configuration file.
        | This is the same command executed at `Magpie` startup using files defined through configuration settings.
    * - ``magpie_run_database_migration``
      - | Run any required database migration operation, according to detected database state and required one by
          the current `Magpie` version.
        | This operation is the same command that is executed at `Magpie` startup to ensure data integrity.
    * - ``magpie_send_email``
      - | Sends an email generated from the selected template contents and SMTP connection configured from
          application settings retrieved from the INI file.
    * - ``magpie_sync_resources``
      - | Synchronizes local and remote resources based on `Magpie` service's ``sync-type`` methodology.
        | See also `magpie-cron`_.


For convenience, a generic entrypoint ``magpie_cli`` is also provided which allows calling each of the other *helper*
operations directly. You can therefore do as follows.

.. code-block:: console

    # list of available 'helper' commands
    magpie_cli --help
    # arguments of the given helper
    magpie_cli [helper] --help


For example, the two statements below are equivalent.

.. code-block:: console

    magpie_cli register_providers [...]
    # OR
    magpie_register_providers [...]


When using an ``conda`` environment, you should be able to directly call the ``magpie_cli`` CLI as above if you
previously installed the package (see :ref:`installation`).

.. _installation: installation.rst

Source code of these helpers can be found `here <https://github.com/Ouranosinc/Magpie/tree/master/magpie/cli>`_.

.. note::
    For backward compatibility reasons, ``magpie_helper`` remains and alias to ``magpie_cli``, but they are exactly
    the same utility.

.. _utilities_connection:

Magpie Connection
---------------------

The repository `Ouranosinc/requests-magpie`_ offers basic Authentication connection to a running `Magpie` instance
similarly to how traditional ``HTTPBasicAuth`` works under the hood. Using this, you can easily plug-and-play `Magpie`
in order to use it with the standard ``requests`` library by passing ``auth=MagpieAuth(<...>)``.

.. _utilities_adapter:

Magpie Adapter: Integration with Twitcher
----------------------------------------------

The class :py:class:`magpie.adapter.MagpieAdapter`
(`source <https://github.com/Ouranosinc/Magpie/blob/master/magpie/adapter/__init__>`_) allows an easy integration with
the :term:`Proxy` service `Twitcher`_. This allows the user to setup a server (i.e.: using `docker-compose`_ or similar)
that can easily integrate a complete user :term:`Authentication` and :term:`Authorization` chain by having `Twitcher`_
ask `Magpie` for the targeted :term:`Service`/:term:`Resource` access permissions via the adapter upon receiving an
HTTP(S) request.

On each new version build of the `Magpie` Docker image, a corresponding Docker image is built as
``pavics/twitcher:magpie-<version>`` with pre-configured adapter within `Twitcher`_ so that both can be used together.

Furthermore, when the above Docker image is used with the integrated adapter, a new HTTP ``POST`` request on route
``/verify`` is added to `Twitcher`_. This method allows to test if an authentication token cookie generated by `Magpie`
(from login via API or UI) is valid and correctly interpreted by the `Twitcher`_ instance. This can be quite useful to
confirm that both instances were adequately configured as both require to share the same ``magpie.secret`` configuration
(amongst many other settings) in order to lookup and authenticate users correctly from incoming HTTP requests.

.. _docker-compose: https://docs.docker.com/compose/
