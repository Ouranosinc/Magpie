:mod:`magpie.api`
=================

.. py:module:: magpie.api


Subpackages
-----------
.. toctree::
   :titlesonly:
   :maxdepth: 3

   home/index.rst
   login/index.rst
   management/index.rst
   swagger/index.rst


Submodules
----------
.. toctree::
   :titlesonly:
   :maxdepth: 1

   exception/index.rst
   generic/index.rst
   requests/index.rst
   schemas/index.rst


Package Contents
----------------

.. function:: get_logger(name, level=None)
   Immediately sets the logger level to avoid duplicate log outputs from the `root logger` and `this logger` when
   `level` is `NOTSET`.


.. data:: LOGGER
   

   

.. function:: includeme(config)

