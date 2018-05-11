======================================
Magpie: A RestFul AuthN/AuthZ service
======================================
Magpie (the smart-bird)
  *a very smart bird who knows everything about you.*

Magpie is service for AuthN/AuthZ accessible via a `RestAPI`_ implemented with the Pyramid web framework. It allows you to manage User/Group/Resource/permission with a postgres database. Behind the scene, it uses `Ziggurat-Foundations`_ and `Authomatic`_.


Build package
=============

.. code-block:: shell
    $ conda create -n magpie
    $ source activate magpie
    $ make install


Installation
============

At the command line::

    $ pip install magpie


.. _RestAPI: https://swaggerhub.com/apis/fderue/magpie-rest_api
.. _Authomatic: https://authomatic.github.io/authomatic/
.. _Ziggurat-Foundations: https://github.com/ergo/ziggurat_foundations

An administration interface is also provided:

.. raw:: html

    <img src="https://www.dropbox.com/s/glhpg3amoblktyt/magpieDemo.gif?raw=1" width="1200px">
