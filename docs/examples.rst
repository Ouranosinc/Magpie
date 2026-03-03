.. _examples:

Examples
========

This section contains example configurations for Magpie that further illustrate how the Magpie software can be used.

Network
-------

This example contains a docker compose configuration to create 3 local magpie deployments, all of which are networked
together using the Magpie :ref:`network_mode` feature.

Start by copying the files below into a directory and then running:

.. code::shell

    docker compose up -d


Once the stack has started then 3 magpie instance will be available on the host machine at:

* http://host.docker.internal/magpie1
* http://host.docker.internal/magpie2
* http://host.docker.internal/magpie3

Note that this will run on port 80 on the host machine so we recommend not running this on a machine that exposes port
80 to your network.

Each instance is created with 3 users:

* test1
* test2
* test3

and an admin user with the username "admin". All users have the same password: ``qwertyqwerty!``

You can log in to any of the three Magpie instances as any of those users and explore the Network feature.

Some things you can do:

Link two user in the network:

* log in to the magpie1 instance as test1
* go to http://host.docker.internal/magpie1/ui/users/current
* click the "Create" button beside magpie2 in the "Network Account Links" table
* sign in to magpie2 as a different user and accept the authorization

Request a token for another instance:

- log in to the magpie1 instance as test1
- request a token for magpie2 by going to http://host.docker.internal/magpie1/network/nodes/magpie2/token

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
