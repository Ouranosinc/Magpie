.. _services:
.. include:: references.rst

===========
Services
===========

This section describes :term:`Service` and underlying :term:`Resource` elements packaged with `Magpie`, as well as
their respective functionalities and intended procedural behavior.

Basic Service and Resource details
------------------------------------

Each :term:`Service` is a specialization of a :term:`Resource` (see: :class:`magpie.models.Service` implementation).
Therefore, they can be listed and searched for either using ``/services`` API routes (using ``service_name``) or using
``/resources`` API routes (with their attributed ``resource_id``), whichever is more convenient for the required needs.

On top of any :term:`Resource`'s metadata, a :term:`Service` provide specific information about its location, its
remote synchronization method (if any), any its exposed endpoint. Another important detail about the :term:`Service`
is its type. This will not only dictate its purpose, but also define the whole schema of allowed :term:`Resource` under
it (if any), as well as every one of their :ref:`Allowed Permissions`.

The final distinction between a :term:`Service` and generic :term:`Resource` is their position in the hierarchy. Only
:term:`Service`-specialized :term:`Resource` (literally ``resource_type = "service"``) are allowed to be placed at the
top of the tree hierarchy. All generic :term:`Resource` nodes must be nested under some root :term:`Service`. Relative
references are indicated using ``parent_id`` and ``root_service_id`` in corresponding :term:`Resource` details.


Available Services
-------------------

.. seealso::
    - :py:mod:`magpie.services`

.. todo:
    listing and explanation/features of every available service types, their 'effective permission' resolution, etc.
    https://github.com/Ouranosinc/Magpie/issues/332

ServiceAccess
~~~~~~~~~~~~~~~~~~~~~

.. todo:

ServiceAPI
~~~~~~~~~~~~~~~~~~~~~

.. todo:

ServiceTHREDDS
~~~~~~~~~~~~~~~~~~~~~

The implementation of this service is handled by class :class:`magpie.services.ServiceTHREDDS`. It refers to a remote
data server named `Thematic Real-time Environmental Distributed Data Services` (`THREDDS`_). The service employs two (2)
types of :term:`Resources`, namely :class:`magpie.models.Directory` and :class:`magpie.models.File`. All the directory
resources can be nested any number of times, and files can only reside as leaves of the hierarchy, similarly to a
traditional file system. The :term:`Allowed Permissions` on both the :term:`Service` itself or any of its children
:term:`Resource` are :attr:`Permission.BROWSE`, :attr:`Permission.READ`, and :attr:`Permission.WRITE` (see note below
regarding this last permission).

.. versionadded:: 3.1
    The :attr:`Permission.BROWSE` permission is used to provide listing access of contents when targeting a
    :term:`Resource` of type :class:`magpie.models.Directory`. When targeting a :class:`magpie.models.File`, it instead
    provides *metadata* access to that file.

Permission :attr:`Permission.READ` can be applied to all of the resources, but will only effectively make sense when
attempting access of a specific :term:`Resource of type :class:`magpie.models.File`.

.. versionchanged:: 3.1
    Permission :attr:`Permission.READ` does not offer *metadata* content listing of :class:`magpie.models.Directory`
    anymore. For this, :attr:`Permission.BROWSE` should be used instead. Setting :attr:`Permission.READ` on a
    directory will only be logical when combined with :attr:`Scope.RECURSIVE`, in which case `Magpie` will interpret
    the :term:`Effective Permissions` to allow read access to all :class:`magpie.models.File` under that directory, at
    any depth level, unless denied by a lower-level specification.

Finally, :attr:`Permission.WRITE` can also be applied on all of the resources, but are not explicitly employed during
parsing of incoming requests.

.. note::
    The :attr:`Permission.WRITE` is not handled by `ServiceTHREDDS`_ itself during :term:`ACL` resolution as it is not
    considered by :meth:`magpie.services.ServiceTHREDDS.permission_requested` that never returns this value. The method
    only returns either :attr:`Permission.BROWSE` or :attr:`Permission.READ`. An :term:`User` or :term:`Group` can still
    have this :term:`Applied Permission` to allow a third party service to interrogate `Magpie API` about the presence
    of :attr:`Permission.WRITE` permission and perform the appropriate action with the result. The
    :term:`Effective Permissions` API routes will provide the resolved ``access``. It is only `Twitcher`_ proxy that
    will not be able to make use of it during incoming requests as it depends on
    :class:`magpie.adapter.magpieowssecurity.MagpieOWSSecurity`, which in turn employs the result from the :term:`ACL`.

    The :attr:`Permission.WRITE` is mostly preserved for backward compatibility of services that employed
    `ServiceTHREDDS`_ to obtain information about which directory or files (which registered `Magpie` :term:`Resource`)
    are writable or not, although using another upload methodology that is not specifically executed via the actual
    remote `THREDDS`_ service.


As presented above, the main two permissions are :attr:`Permission.BROWSE` and :attr:`Permission.READ` which
correspondingly serve to retrieve *metadata* and actual *data* of a given :term:`Resource`. To distinguish requests
between these two types of contents, `ServiceTHREDDS`_ employs two parts from the request path, the sub-path *prefix*
and the file *extension*. A default methodology is employed categorize these two types of content, but can be modified
using custom configurations as described in :ref:`Custom THREDDS Settings` section.




Custom THREDDS Settings
~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
    See section :ref:`ServiceTHREDDS` about the base implementation components of this service type for further details.


With either the `providers.cfg`_ or the `Combined Configuration File`_ presented in previous sections, a service of
type `THREDDS`_ can be slightly customized to meet the intended needs. Specifically, two additional fields
``metadata_type`` and ``data_type


As presented above, the main two permissions are :attr:`Permission.BROWSE` and :attr:`Permission.READ` which
correspondingly serve to retrieve *metadata* and actual *data* of a given :term:`Resource`. To distinguish requests
between these two types of contents, `ServiceTHREDDS`_ employs two parts from the request path, the sub-path *prefix*
and the file *extension*. The *default* methodology employed to categorize these two types of content is presented
below.

.. code-block:: YAML

    providers:
      thredds_service:
        data_type:
          - prefix: fileServer
          - prefix: dodsC
          - prefix: wcs
          - prefix: wms
        metadata_type:
          # no extra sub-path, case when navigating contents using an UI browser
          # (`~` is the representation method of JSON's `null`, make sure to adjust accordingly with file extension)
          - prefix: ~
          - prefix: catalog
          - prefix: ncml
          - prefix: uddc
          - prefix: iso



.. note::
    The *default* categorization between *metadata*/*data* contents can be modified using custom configurations
    specified within a `providers.cfg`_ or :ref:`Combined Configuration File`.


ServiceGeoserverWMS
~~~~~~~~~~~~~~~~~~~~~

.. todo:

ServiceNCWMS2
~~~~~~~~~~~~~~~~~~~~~

.. todo:

ServiceWMS
~~~~~~~~~~~~~~~~~~~~~

.. todo:

ServiceWPS
~~~~~~~~~~~~~~~~~~~~~

.. todo:


Adding Service Types
-----------------------

.. todo:
    dynamic custom service definition
    https://github.com/Ouranosinc/Magpie/issues/149
.. todo: even if not implementing above, could be good to document fields or ServiceInterface for future reference

Service Synchronization
------------------------

.. todo:
    resource auto-sync feature for a given service and cron configuration setup for it

.. seealso::

    Utility ``magpie_sync_resources`` in `Magpie CLI Helpers`_ is also available to manually launch a :term:`Resource`
    synchronization operation for supporting :term:`Service`-types.
