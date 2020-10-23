.. _installation:
.. include:: references.rst

=============
Installation
=============

At the command line::

    pip install magpie

Or, if you have conda installed::

    conda create -n magpie
    conda activate magpie
    pip install magpie


All above is done automatically with::

    make install-pkg


If you want the full setup for development (including dependencies for test execution), use::

    make install-dev


You can run the Magpie container with a ``docker-compose.yml`` for a local setup (see `docker-compose.yml.example`_)


Backward Compatibility
--------------------------

`Magpie` remains available for following obsolete and backward compatible versions.

- Python 2.7 (end of life on January 1st, 2020)
- Python 3.5 (end of life on September 13th, 2020)

Older versions than ones listed above are unsupported. These oldest versions remain tested in `Travis-CI` and deployment
procedure for traceability, but are not guaranteed to work, nor provide all functional or security features and will not
be actively maintained. If you identify a easy fix for such an older version, please submit an `issue`_ to be considered
for integration. It is greatly recommended to upgrade your Python version to receive all applicable security patches.
