.. _services:
.. include:: references.rst

===========
Services
===========

This section describes :term:`Service` and underlying :term:`Resource` elements packaged with `Magpie`, as well as
their respective functionalities and intended procedural behavior. Section :ref:`service_impl` first presents the
general details to implement all :term:`Service` implementations, followed by section :ref:`services_available` which
details specific implementations.

.. _service_impl:

Basic Service and Resource details
------------------------------------

Each :term:`Service` is a specialization of a :term:`Resource` (see: :class:`magpie.models.Service` implementation).
Therefore, they can be listed and searched for either using ``/services`` API routes (using ``service_name``) or using
``/resources`` API routes (with their attributed ``resource_id``), whichever is more convenient for the required needs.

On top of any :term:`Resource`'s metadata, a :term:`Service` provides specific information about its location, its
remote synchronization method (if any), and its exposed endpoint. Another important detail about the :term:`Service`
is its ``type``. This will not only dictate its purpose, but also define the whole schema of allowed :term:`Resource`
under it (if any), as well as every one of their :term:`Allowed Permissions`.

The final distinction between a :term:`Service` and generic :term:`Resource` is their position in the hierarchy. Only
:term:`Service`-specialized :term:`Resource` (literally ``resource_type = "service"``) are allowed to be placed at the
top of the tree hierarchy. All generic :term:`Resource` nodes must be nested under some root :term:`Service`. Relative
references are indicated using ``parent_id`` and ``root_service_id`` in corresponding :term:`Resource` details.

Every :term:`Service` type provided by `Magpie` must derive from :class:`magpie.services.ServiceInterface`. Each
specific implementation (see :ref:`services_available`) serves to convert a given incoming HTTP request components
(method, path, query parameters, body, etc.) into the appropriate :term:`Service`, :term:`Resource` and
:term:`Permission` elements. This ultimately provides the required elements to resolve :term:`ACL` access of a
:term:`Request User` toward the targeted :term:`Resource` according to its :term:`Effective Permissions`.

In order to implement a new :term:`Service` type, two (2) methods and a few attributes are required. The first method is
:meth:`magpie.services.ServiceInterface.permission_requested` which basically indicates how the HTTP request should be
interpreted into a given :class:`Permission`. The second is :meth:`magpie.services.ServiceInterface.resource_requested`
which similarly tells the interpretation method to convert the request into a :class:`magpie.models.Resource` reference.

Whenever :term:`Effective Permissions` or :term:`ACL` needs to be resolved in order to determine if a
:term:`Request User` can have access or not to a :term:`Resource`, `Magpie` will employ the appropriate :term:`Service`
implementation and call the methods to process the result.

.. versionchanged:: 3.0
    All the resolution of :class:`Access <magpie.permissions.Access>` and :class:`Scope <magpie.permissions.Scope>`
    modifiers are automatically handled according to the applied :term:`Permission` on the :term:`Resource` hierarchy.
    Therefore, no specific action is required to support these features for new :term:`Service` implementations.
    See :ref:`permission_modifiers` for details.

On top of the above methods, the following attributes must be defined.


.. |br| raw:: html

    <br>

.. temporarily use services module to reduce displayed name in table
.. py:currentmodule:: magpie.services


.. list-table::
    :header-rows: 1

    * - Attribute
      - Description
    * - :attr:`ServiceInterface.service_type` |br| (``str``)
      - Defines the mapping of registered :term:`Service` to the appropriate implementation type. Each implementation
        must have an unique value.
    * - :attr:`ServiceInterface.permissions` |br| (``List[Permission]``)
      - Defines the :term:`Allowed Permissions` that can be applied onto the :term:`Service` reference itself.
    * - :attr:`ServiceInterface.resource_types_permissions` |br| (``Dict[Resource, List[Permission]]``)
      - Map of the allowed children :term:`Resource` under the :term:`Service` and their corresponding
        :term:`Allowed Permissions` for each case. Leaving this map empty will disallow the creation of any children
        :term:`Resource`, making the :term:`Service` the unique applicable element of the hierarchy. Note that each
        :term:`Resource` implemented by a derived class of :class:`magpie.models.Resource` also provides details about
        :Term:`Allowed Permissions`, their type and further nested children :term:`Resource`.
    * - :attr:`ServiceInterface.params_expected` |br| (``List[str]``)
      - Represents specific parameter names that can be preprocessed during HTTP request parsing to ease following
        resolution of :term:`ACL` use-cases. Employed most notably by :term:`Services` based on
        :class:`magpie.services.ServiceOWS`.


.. _services_available:

Available Services
-------------------

.. employ the permissions as base for this section to ease reading by shorter reference definitions
.. py:currentmodule:: magpie.permissions

.. seealso::
    Module :py:mod:`magpie.services` contains the implementation of every :term:`Service` presented below.

.. seealso::
    Multiple of the following implementation details require comprehension of the concepts introduced in
    :ref:`permission_modifiers`. Consider looking this up if descriptions feel hard to understand at first glance.


ServiceAccess
~~~~~~~~~~~~~~~~~~~~~

The implementation of this :term:`Service` is handled by class :class:`magpie.services.ServiceAccess`. It is intended to
act as a simple *all-or-nothing* endpoint barrier, where only :attr:`Permission.ACCESS` can be applied, and only
directly on the :term:`Service` itself. A :term:`User` or :term:`Group` that has that :term:`Permission` with
:attr:`Access.ALLOW` will be able to reach the :term:`Service`. Any other operation (or explicit :attr:`Access.DENY`)
will all result into denied access to the private URL registered by the :term:`Service`.

.. versionchanged:: 3.0
    This :term:`Service` implementation dates prior to the integration of :class:`Access` and :class:`Scope` concepts
    that now provides modifiers to the :term:`Permission` resolution methodology, notably prior to the addition of
    :attr:`Access.DENY`. This :term:`Service` is equivalent to a simplified version of the fine-grained `ServiceAPI`_
    alternative where no children :term:`Resource` would be registered.

.. note::
    Due to the single-level aspect of this :term:`Service`, the :attr:`Scope` :term:`Permission` modifier does not
    have any effect.

ServiceAPI
~~~~~~~~~~~~~~~~~~~~~

The implementation of this :term:`Service` is handled by class :class:`magpie.services.ServiceAPI`. It refers to a
remote URL endpoint that should have a :term:`Resource` tree formed out of the path segments. The :term:`Service` only
has one (1) type of :term:`Resource`, namely :class:`magpie.models.Route`, that can have an unlimited amount of nested
children of the same type. The :term:`Allowed Permissions` for this :term:`Service` are :attr:`Permission.READ` and
:attr:`Permission.WRITE`. All requests using ``GET`` or ``HEAD`` are mapped to :attr:`Permission.READ` access while all
other HTTP methods represent a :attr:`Permission.WRITE` access.

Request path segments follow the natural hierarchy of the nested :class:`magpie.models.Route` under the :term:`Service`.
For example, a proxy employing :class:`magpie.adapter.MagpieAdapter` such that ``{PROXY_URL}`` is the base of the
request path and the :class:`magpie.services.ServiceAPI` named ``SomeAPI`` was registered would be mapped against
each sub-:term:`Resource` as presented below.

.. code-block::

    {PROXY_URL}/SomeAPI/some-resource/child_resource/final
    {PROXY_URL}/SomeAPI/other-resource/subResource

.. code-block::

    SomeAPI                     [service: ServiceAPI]
        some-resource           [resource: Route]
            child_resource      [resource: Route]
                final           [resource: Route]
        other-resource          [resource: Route]
            subResource         [resource: Route]


Every :class:`magpie.models.Route` as well as the :term:`Service` itself can have the :term:`Permission` based on the
HTTP method of the incoming request. All :class:`Access` and :class:`Scope` modifiers are also supported for highly
customizable :term:`ACL` combinations. See :ref:`permission_modifiers` for further details.

ServiceTHREDDS
~~~~~~~~~~~~~~~~~~~~~

The implementation of this :term:`Service` is handled by class :class:`magpie.services.ServiceTHREDDS`. It refers to a
remote data server named `Thematic Real-time Environmental Distributed Data Services` (`THREDDS`_). The :term:`Service`
employs two (2) types of :term:`Resources`, namely :class:`magpie.models.Directory` and :class:`magpie.models.File`.
All the directory resources can be nested any number of times, and files can only reside as leaves of the hierarchy,
similarly to a traditional file system. The :term:`Allowed Permissions` on both the :term:`Service` itself or any of
its children :term:`Resource` are :attr:`Permission.BROWSE`, :attr:`Permission.READ`, and :attr:`Permission.WRITE`
(see note below regarding this last permission).

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
    only returns either :attr:`Permission.BROWSE` or :attr:`Permission.READ`. A :term:`User` or :term:`Group` can still
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
and the file *extension*. The *default* methodology employed to categorize these two types of content is represented
by the below configuration.

.. note::
    A custom categorization between *metadata* and *data* contents can be provided With either the `providers.cfg`_ or
    a :ref:`config_file` as described in greater lengths within the :ref:`configuration_link` chapter.

.. code-block:: YAML

    providers:
      LocalThredds:
        # minimal configuration requirements (where the real `THREDDS` service resides)
        # other optional parameters from `providers.cfg` can also be provided
        url: http://localhost:1234
        type: thredds

        # customizable request parsing methodology (specific to `thredds` type)
        file_patterns:
          - .*.nc
        metadata_type:
          prefixes:
            - null  # note: special YAML value evaluated as `no-prefix`, use quotes if literal value is needed
            - catalog
            - ncml
            - uddc
            - iso
        data_type:
          prefixes:
            - fileServer
            - dodsC
            - dap4
            - wcs
            - wms

Assuming a proxy intended to receive incoming requests configured with :class:`magpie.adapter.MagpieAdapter` such that
``{PROXY_URL}`` is the base path, the following path would point toward the above registered service::

    {PROXY_URL}/LocalThredds


An incoming request will be parsed according to configured values against the following format::

    {PROXY_URL}/LocalThredds/<prefix>/.../<file>

The above template demonstrates that `Magpie` will attempt to match the ``<prefix>`` part with any of the listed
``prefixes`` in the configuration. If a match is found, the corresponding *metadata* or *data* content will be assumed,
according to where the match entry was located, to determine whether the requested :term:`Resource` should be validated
respectively for :attr:`Permission.BROWSE` or :attr:`Permission.READ` access. If no ``<prefix>`` can be resolved, the
permission will be immediately assumed as :attr:`Access.DENY` regardless of type. To allow top-level access directly on
the :term:`Service`'s root without ``<prefix>``, it is important to provide ``null`` within the desired ``prefixes``
list. Duplicates between the two lists of ``prefixes`` will favor entries in ``metadata_type`` over ``data_type``.

After resolution of the content type from ``<prefix>``, the resolution of any amount of :class:`magpie.models.Directory`
:term:`Resource` will be attempted. Any missing children directory :term:`Resource` will terminate the lookup process
immediately, and :term:`ACL` will be resolved considering :attr:`Scope.RECURSIVE` if any applicable parent
:term:`Resources` for the given :term:`Permission` selected by ``<prefix>`` and from where lookup stopped.

Once the last element of the path is reached, the ``file_patterns`` will be applied against ``<file>`` in order to
attempt extracting the targeted :class:`magpie.models.File` :term:`Resource`. Patterns are applied until the first
positive match is found. Therefore, order is important if providing multiple. If there is a match, that value will be
used to lookup the :term:`Resource`. Otherwise, the plain ``<file>`` name is used directly. The plain name is also used
if ``file_patterns`` is specified as empty or ``null``. Not explicitly overriding the field will result into using the
above *default* ``file_patterns``. The ``file_patterns`` allow for example to consider ``file.nc``, ``file.ncml`` and
``file.nc.html`` as the same :term:`Resource` internally, which avoids duplicating :term:`Applied Permissions` across
multiple :term:`Resource` for every *metadata* or *data* representation.

ServiceBaseWMS
~~~~~~~~~~~~~~~~~~~~~

.. seealso::

    Derived implementations:

    - `ServiceGeoserverWMS`_
    - `ServiceNCWMS2`_

This is a *partial base* class employed to represent :term:`OWS` `Web Map Service` extended via other complete classes.
It cannot be employed directly as :term:`Service` instance. The derived classes provide different parsing methodologies
and children :term:`Resource` representation according to their respective functionalities.

It provides support for the following permissions, each corresponding to the appropriate functionality of `WMS`:

- :attr:`Permission.GET_CAPABILITIES`
- :attr:`Permission.GET_MAP`
- :attr:`Permission.GET_FEATURE_INFO`
- :attr:`Permission.GET_LEGEND_GRAPHIC`
- :attr:`Permission.GET_METADATA`

Similar to any other :term:`OWS` based :term:`Service`, the HTTP request takes a ``request`` query parameter that
indicates which of the above :term:`Permission` is being requested.


ServiceGeoserverWMS
~~~~~~~~~~~~~~~~~~~~~

.. seealso::

    Base class: `ServiceBaseWMS`_

This implementation is defined by :class:`magpie.services.ServiceGeoserverWMS`. It extends the base class by using
children :term:`Resource` defined by :class:`magpie.models.Workspace`, which supports the same set of :term:`Permission`
as their parent :term:`Service`. Each of those :class:`magpie.models.Workspace` correspond to the equivalent element
provided to `GeoServer`_ based HTTP request using query parameter ``layers``, following format
``layers=<Workspace>:<LayerName>``. The :term:`Permission` is obtained from the ``request`` query parameter.

.. warning::
    As of latest version of `Magpie`, there is no specific handling of the specific ``LayerName`` part of the targeted
    :term:`Resource`. Please submit an `issue`_ with specific use-case if this is something that would be required.


ServiceNCWMS2
~~~~~~~~~~~~~~~~~~~~~

.. seealso::

    Base class: `ServiceBaseWMS`_

This implementation is defined by :class:`magpie.services.ServiceNCWMS2`. It extends the base class by using
children :term:`Resource` defined as :class:`magpie.models.Directory` and :class:`magpie.models.File` instances but,
using the corresponding :term:`Permission` entries from `ServiceBaseWMS`_ class instead of the default
:attr:`Permission.READ` and :attr:`Permission.WRITE` (i.e.: see `ServiceTHREDDS`_). The general idea is that the remote
`ncWMS2`_ *service provider* being represented by this :term:`Service` points to the same `NetCDF` file resources as
offered by `THREDDS`, but for mapping display. The HTTP request therefore points toward another proxy endpoint and
employs different query parameters specific to `WMS` requests (instead of `THREDDS`), although the provided file
reference is technically the same. For this reason, the same :term:`Resource` hierarchy is supported, with any number
of nested :class:`magpie.models.Directory` and :class:`magpie.models.File` as leaves. The targeted :term:`Resource` by
the HTTP request is extracted from either the ``dataset``, ``layername`` or ``layers`` query parameter formatted as
relative file path from the ``THREDDS` root. The applicable query parameter depends on the appropriate
:term:`Permission` being requested based on the provided ``request`` query parameter.

.. note::
    Although the class name employs ``NCWMS2``, the registered type is represented by the string ``ncwms`` for
    executing requests toward the `Magpie` API and contents returned in its responses.


ServiceWPS
~~~~~~~~~~~~~~~~~~~~~

The implementation of this :term:`Service` is handled by class :class:`magpie.services.ServiceWPS`. It is intended to
control access to the operations provided by an :term:`OWS` `Web Processing Service`. This :term:`Service` allows
one (1) type of child :term:`Resource`, namely the :class:`magpie.models.Process` which represent the execution units
that are registered under a remote `WPS`. Every :class:`magpie.models.Process` cannot itself have a child
:term:`Resource`, making `ServiceWPS`_ maximally a 2-tier level hierarchy.

There are three (3) types of :term:`Allowed Permissions` which each represent an operation that can be requested from it
(via ``request`` query parameter value of the HTTP request), specifically the :attr:`Permission.GET_CAPABILITIES`,
:attr:`Permission.DESCRIBE_PROCESS`, and :attr:`Permission.EXECUTE`. The :attr:`Permission.GET_CAPABILITIES`
corresponds to the retrieval of available list of *Processes* on the `WPS` instance, and therefore, can only be applied
on the top-level :term:`Service`. The other two permissions can be applied on either the :term:`Service` or specifically
on individual :class:`magpie.models.Process` :term:`Resource` definitions. When applied to the :term:`Service` with
:attr:`Scope.RECURSIVE` modifier, the corresponding :term:`Permission` becomes effective to all underlying *Processes*.
Otherwise, the :term:`Permission` applied on specific :class:`magpie.models.Process` entries control the specific
:term:`ACL` only for it. When a specific :term:`Permission` is involved on a :class:`magpie.models.Process` during
:term:`Effective Permissions` resolution, the value of the query parameter ``identifier`` is employ to attempt mapping
it against an existing :term:`Resource`. The resolution of :term:`Effective Permissions` in even of multi-level tree
:term:`Resource` is computed in the usual manner described in the :ref:`Permissions` chapter.


.. warning::
    When applying permissions on a per-:class:`magpie.models.Process` basis, :attr:`Scope.MATCH` modifier is recommended
    if only a specific ``request`` should be granted access, although :attr:`Scope.RECURSIVE` would have the same effect
    currently because these resources are necessarily leaf nodes by definition. This is to prevent unexpectedly granting
    additional lower-level :term:`Resource` access in the event this definition gets modified or extended in the future.



..
    Adding Service Types
    -----------------------
    dynamic custom service definition

.. todo: Add dynamic services if implemented (https://github.com/Ouranosinc/Magpie/issues/149)


Service Synchronization
------------------------

.. versionadded:: 0.7

Some :term:`Service` implementations offer a synchronization feature which is represented by field ``sync_type`` within
`Magpie` API responses. When this option is available, the corresponding :term:`Service` is able to query the real
*remote service provider* to retrieve actual :term:`Resource` nested under it. This allows quick generation of the full
:term:`Resource` tree hierarchy rather than manually creating each element.

.. note::
    If only :attr:`Scope.RECURSIVE` :term:`Permission` are being applied on the :term:`Service` or their children
    :term:`Resource`, it is better to enter *fewer* children element in the tree to reduce computation time of
    :term:`Effective Permissions`. The complete hierarchy should be employed only when the depth of the tree is
    relatively shallow or that :attr:`Scope.MATCH` must be applied specifically for some :term:`Resource` to obtain
    desired access behaviour.

When using the `Magpie` Docker image, the default command run the `magpie-cron`_ utility in parallel to the API. This
cron job will periodically execute the :term:`Resource` auto-synchronization feature for a given :term:`Service` that
supports it.

.. seealso::

    Utility ``magpie_sync_resources`` in :ref:`utilities_helpers` is also available to manually launch a
    :term:`Resource` synchronization operation from the command line for supporting :term:`Service`-types.
    This is the same operation that gets executed by `magpie-cron`_.
