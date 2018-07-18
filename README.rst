======================================
Magpie: A RestFul AuthN/AuthZ service
======================================
Magpie (the smart-bird)
  *a very smart bird who knows everything about you.*

Magpie is service for AuthN/AuthZ accessible via a `RestAPI`_ implemented with the Pyramid web framework. It allows you to manage User/Group/Resource/permission with a postgres database. Behind the scene, it uses `Ziggurat-Foundations`_ and `Authomatic`_.

REST API Documentation
======================

The documentation is auto-generated and served under `{HOSTNAME}/magpie/api/` using Swagger-UI with tag `latest`.
For convenience, older API versions are also provided.


Build package
=============

At the command line::

    $ conda create -n magpie
    $ source activate magpie
    $ make install


Installation
============

At the command line::

    $ pip install magpie


.. _RestAPI: https://swaggerhub.com/apis/CRIM/magpie-rest_api
.. _Authomatic: https://authomatic.github.io/authomatic/
.. _Ziggurat-Foundations: https://github.com/ergo/ziggurat_foundations

An administration interface is also provided:

.. raw:: html

    <img src="https://www.dropbox.com/s/glhpg3amoblktyt/magpieDemo.gif?raw=1" width="1200px">
