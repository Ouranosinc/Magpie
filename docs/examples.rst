.. _examples:

Examples
========

This section contains example configurations for `Magpie` that further illustrate how the software can be used.

.. _examples_network:

Network
-------

This example contains a ``docker compose`` configuration to create 3 local `Magpie` deployments, all of which are
networked together using the Magpie :ref:`network_mode` feature.

.. seealso::
    :reF:`Example Network Files <examples_network_files>`

.. _examples_network_setup:

Setup
~~~~~

Start by copying the files below into a directory and then running:

.. code-block:: shell

    docker compose up -d


Once the stack has started then 3 `Magpie` instance will be available on the host machine at:

* http://host.docker.internal/magpie1
* http://host.docker.internal/magpie2
* http://host.docker.internal/magpie3

Note that this will run on port 80 on the host machine so we recommend not running this on a machine that exposes port
80 to your network.

Each instance is created with 3 users (``test1``, ``test2``, ``test3``)
and an *administrator* user with the username ``admin``. All users have the same password: ``qwertyqwerty!``.

You can log in to any of the three `Magpie` instances as any of those users and explore the :ref:`network_mode`
feature.

.. _examples_network_usage:

Usage
~~~~~

Once the example instances are running with Network mode, you can do any of the following operations.

* Link two users in the network:

  1. log in to the ``magpie1`` instance as ``test1``
  2. go to http://host.docker.internal/magpie1/ui/users/current
  3. click the "*Create*" button beside ``magpie2`` in the "*Network Account Links*" table
  4. sign in to ``magpie2`` as a different user and accept the authorization

* Request a token for another instance:

  1. log in to the ``magpie1`` instance as ``test1``
  2. request a token for ``magpie2`` by going to http://host.docker.internal/magpie1/network/nodes/magpie2/token

.. _examples_network_files:

Files
~~~~~
Download all files below into the same directory in order to run this example.

docker-compose.yml
^^^^^^^^^^^^^^^^^^
.. literalinclude:: _examples/network/docker-compose.yml
    :language: yaml

init.sh
^^^^^^^
.. literalinclude:: _examples/network/init.sh
    :language: shell

nginx.conf
^^^^^^^^^^
.. literalinclude:: _examples/network/nginx.conf
    :language: nginx

magpie-entrypoint.sh
^^^^^^^^^^^^^^^^^^^^
.. literalinclude:: _examples/network/magpie-entrypoint.sh
    :language: shell
