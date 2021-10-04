.. include:: references.rst
.. _installation:

Installation
=============

Please consider all following commands to pick the combination that better fits your needs.
These are not a set of commands to call one after the other to "setup magpie", but rather a list of different
methods that lead to equivalent results employed for different use cases.

To install as an external package, you can clone and install from the directory by running at the command line:

.. code-block:: console

    git clone https://github.com/Ouranosinc/Magpie magpie
    pip install ./magpie   # watch out, directory, not 'magpie' package

.. warning::

    Do **NOT** run ``pip install magpie`` directly, as this installs another package from PyPI also named ``magpie``
    that is not this `Magpie` application. Instead, make sure to refer to your local directory where `Magpie`
    repository has been cloned, or select another method below.

Alternatively, the package can be installed directly from the repository with the following command.
This is recommended if you only want to employ `Magpie` (as CLI or WebApp) but not develop with it directly.

.. code-block:: console

    pip install git+https://github.com/Ouranosinc/Magpie.git

If you desire to develop code features or fixes with `Magpie`, consider using the ``-e`` option to install a reference
to your local installation, avoiding distinct instances locally and in ``site-packages``. For example:

.. code-block:: console

    pip install -e <local-magpie-directory>

If you have ``conda`` installed, you can create an environment and activate it as follows:

.. code-block:: console

    conda create -n magpie
    conda activate magpie
    pip install magpie

All above operations is done automatically with the following command executed from within a local `Magpie` directory:

.. code-block:: console

    make install-pkg

If you want the full setup for development (including dependencies for test execution), use:

.. code-block:: console

    make install-dev


You can run the Magpie container with a ``docker-compose.yml`` for a local setup (see `docker-compose.yml.example`_)


Backward Compatibility
--------------------------

`Magpie` remains available for following obsolete and backward compatible versions.

- Python 2.7 (end of life on January 1st, 2020)
- Python 3.5 (end of life on September 13th, 2020)

Older versions than ones listed above are unsupported. These oldest versions remain tested in `Travis-CI` and deployment
procedure for traceability, but are not guaranteed to work, nor provide all functional or security features and will not
be actively maintained. If you identify an easy fix for such an older version, please submit an `issue`_ to be
considered for integration. It is greatly recommended to upgrade your Python version to receive all applicable security
patches.

Installation for Twitcher
-------------------------

If you are planning on using `Magpie` as an adapter to `Twitcher`_ :term:`Proxy`, please employ the |twitcher_0_5_x|_.
Earlier version (e.g.: ``0.6.0``) broke compatibility to load the :class:`magpie.adapter.MagpieAdapter` class to make
them work together.

.. seealso::
    Refer to :ref:`authz_protected_resources` to learn more about `Twitcher`_ and its interaction with `Magpie`.

.. |twitcher_0_5_x| replace:: Twitcher 0.5.x branch
.. _twitcher_0_5_x: https://github.com/bird-house/twitcher/tree/0.5.x
