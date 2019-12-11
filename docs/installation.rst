Installation
============

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


You can run the Magpie container with a docker-compose.yml for a local setup (see docker-compose.yml.example)
