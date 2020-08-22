.. _services:
.. include:: references.rst

===========
Services
===========

This section describes :term:`Service` and underlying :term:`Resource` elements packaged with `Magpie`, as well as
their respective functionalities and intended procedural behavior.

Available Services
-------------------

.. todo:
    listing and explanation/features of every available service types, their 'effective permission' resolution, etc.
    https://github.com/Ouranosinc/Magpie/issues/332

.. seealso::
    - :py:mod:`magpie.services`

.. todo:
    dynamic custom service definition
    https://github.com/Ouranosinc/Magpie/issues/149
.. todo: even if not implementing above, could be good to document fields or ServiceInterface for future reference

Resource Synchronization
------------------------

.. todo:
    resource auto-sync feature for a given service and cron configuration setup for it

.. seealso::

    Utility ``magpie_sync_resources`` in `Magpie CLI Helpers`_ is also available to manually launch a :term:`Resource`
    synchronization operation for supporting :term:`Service`-types.
