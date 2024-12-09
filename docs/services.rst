.. _services:
.. include:: references.rst

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
under it (if any), as well as every one of their :term:`Allowed Permissions <Allowed Permission>`.

The final distinction between a :term:`Service` and generic :term:`Resource` is their position in the hierarchy. Only
:term:`Service`-specialized :term:`Resource` (literally ``resource_type = "service"``) are allowed to be placed at the
top of the tree hierarchy. All generic :term:`Resource` nodes must be nested under some root :term:`Service`. Relative
references are indicated using ``parent_id`` and ``root_service_id`` in corresponding :term:`Resource` details.

Every :term:`Service` type provided by `Magpie` must derive from :class:`magpie.services.ServiceInterface`. Each
specific implementation (see :ref:`services_available`) serves to convert a given incoming HTTP request components
(method, path, query parameters, body, etc.) into the appropriate :term:`Service`, :term:`Resource` and
:term:`Permission` elements. This ultimately provides the required elements to resolve :term:`ACL` access of a
:term:`Request User` toward the targeted :term:`Resource` according to its
:term:`Effective Permissions <Effective Permission>`.

In order to implement a new :term:`Service` type, two (2) methods and a few attributes are required. The first method is
:meth:`magpie.services.ServiceInterface.permission_requested` which basically indicates how the HTTP request should be
interpreted into a given :class:`Permission`. The second is :meth:`magpie.services.ServiceInterface.resource_requested`
which similarly tells the interpretation method to convert the request into a :class:`magpie.models.Resource` reference.

Whenever :term:`Effective Permission` or :term:`ACL` needs to be resolved in order to determine if a
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
      - Defines the :term:`Allowed Permissions <Allowed Permission>` that can be applied onto the :term:`Service`
        reference itself.
    * - :attr:`ServiceInterface.resource_types_permissions` |br| (``Dict[Resource, List[Permission]]``)
      - Map of the allowed children :term:`Resource` under the :term:`Service` and their corresponding
        :term:`Allowed Permissions <Allowed Permission>` for each case. Leaving this map empty will disallow the
        creation of any children :term:`Resource`, making the :term:`Service` the unique applicable element of the
        hierarchy. Note that each :term:`Resource` implemented by a derived class of :class:`magpie.models.Resource`
        also provides details about :Term:`Allowed Permissions <Allowed Permission>`, their type and further nested
        children :term:`Resource`.
    * - :attr:`child_structure_allowed` |br| (``Dict[Type[ServiceOrResourceType], List[Type[models.Resource]]]``)
      - Map of allowed :term:`Resource` type nesting hierarchy for the :term:`Service`.
        This controls whether some children :term:`Resource` can be placed under another to limit creation only to
        cases that are relevant for the implemented :term:`Service`.
    * - :attr:`configurable` |br| (``bool``)
      - Parameter that controls whether the :term:`Service` supports custom configuration, providing means to
        slightly alter, enable or disable certain behaviours of the parsing methodology of request into :term:`Resource`
        and :term:`Permission` components for the given :term:`Service`.

.. seealso::
    :ref:`ServiceTHREDDS` and :ref:`ServiceGeoserver` for examples of :term:`Service` implementations that
    support custom configuration.

On top of the above definitions, any service that derives from :class:`magpie.services.ServiceOWS` should also provide
follow parameters for parsing :term:`OWS` requests.

.. list-table::
    :header-rows: 1

    * - Attribute
      - Description
    * - :attr:`ServiceOWS.params_expected` |br| (``List[str]``)
      - Represents specific parameter names that can be preprocessed during HTTP request parsing to ease following
        resolution of :term:`ACL` use cases.
    * - :attr:`ServiceOWS.service_base`  |br| (``str``)
      - Provide the reference :term:`OWS` type for handling requests with proper parsers and resolvers.

Furthermore, some :term:`Services <Service>` specifically implement extended :term:`OWS` utilities offered by
`GeoServer`_. They derive from :class:`ServiceGeoserverBase` and should provide the following additional parameters.

.. list-table::
    :header-rows: 1

    * - Attribute
      - Description
    * - :attr:`ServiceGeoserverBase.resource_scoped` |br| (``bool``)
      - Indicates if the :term:`Service` is allowed to employ scoped :class:`models.Workspace` naming, meaning that
        a :term:`Resource` of that type can be extracted either from the request path or the specific request parameter
        using notation format ``<WORKSPACE>:<RESOURCE_PARAM>``.
    * - :attr:`ServiceGeoserverBase.resource_multi` |br| (``bool``)
      - Indicates if the :term:`Service` supports multiple simultaneous :term:`Resource` references within a single
        request (see :ref:`perm_resolution` for more details`), which must all be considered
        for :term:`Effective Resolution`.
    * - :attr:`ServiceGeoserverBase.resource_param` |br| (``Union[Str, List[Str]]``)
      - Name of one or many request query parameter(s) from which to extract multiple equivalent :term:`Resource`
        references when the :term:`Service` supports multiple representations or notation conventions.


.. versionchanged:: 3.21
    - Attribute :attr:`ServiceOWS.params_expected` has been moved from :class:`ServiceInterface` to instead be directly
      under :class:`ServiceOWS` since it applies only to derived classes from that base.

.. versionadded:: 3.21
    - Attribute :attr:`ServiceInterface.child_structure_allowed`
    - Attribute :attr:`ServiceInterface.configurable`
    - Attribute :attr:`ServiceOWS.service_base`
    - Attribute :attr:`ServiceGeoserverBase.resource_scoped`
    - Attribute :attr:`ServiceGeoserverBase.resource_multi`
    - Attribute :attr:`ServiceGeoserverBase.resource_param`


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
children of the same type. The :term:`Allowed Permissions <Allowed Permission>` for this :term:`Service`
are :attr:`Permission.READ` and :attr:`Permission.WRITE`. All requests using ``GET`` or ``HEAD`` are mapped
to :attr:`Permission.READ` access while all other HTTP methods represent a :attr:`Permission.WRITE` access.

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
employs two (2) types of :term:`Resource`, namely :class:`magpie.models.Directory` and :class:`magpie.models.File`.
All the directory resources can be nested any number of times, and files can only reside as leaves of the hierarchy,
similarly to a traditional file system. The :term:`Allowed Permissions <Allowed Permission>` on both the :term:`Service`
itself or any of its children :term:`Resource` are :attr:`Permission.BROWSE`, :attr:`Permission.READ`, and
:attr:`Permission.WRITE` (see note below regarding this last permission).

.. versionadded:: 3.1
    The :attr:`Permission.BROWSE` permission is used to provide listing access of contents when targeting a
    :term:`Resource` of type :class:`magpie.models.Directory`. When targeting a :class:`magpie.models.File`, it instead
    provides *metadata* access to that file.

Permission :attr:`Permission.READ` can be applied to all of the resources, but will only effectively make sense when
attempting access of a specific :term:`Resource` of type :class:`magpie.models.File`.

.. versionchanged:: 3.1
    Permission :attr:`Permission.READ` does not offer *metadata* content listing of :class:`magpie.models.Directory`
    anymore. For this, :attr:`Permission.BROWSE` should be used instead. Setting :attr:`Permission.READ` on a
    directory will only be logical when combined with :attr:`Scope.RECURSIVE`, in which case `Magpie` will interpret
    the :term:`Effective Permission` to allow read access to all :class:`magpie.models.File` under that directory, at
    any depth level, unless denied by a lower-level specification.

Finally, :attr:`Permission.WRITE` can also be applied on all of the resources, but are not explicitly employed during
parsing of incoming requests.

.. note::
    The :attr:`Permission.WRITE` is not handled by `ServiceTHREDDS`_ itself during :term:`ACL` resolution as it is not
    considered by :meth:`magpie.services.ServiceTHREDDS.permission_requested` that never returns this value. The method
    only returns either :attr:`Permission.BROWSE` or :attr:`Permission.READ`. A :term:`User` or :term:`Group` can still
    have this :term:`Applied Permission` to allow a third party service to interrogate `Magpie API` about the presence
    of :attr:`Permission.WRITE` permission and perform the appropriate action with the result. The
    :term:`Effective Permission` API routes will provide the resolved ``access``. It is only `Twitcher`_ proxy that
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
    a :ref:`config_file` as described in greater lengths within the :ref:`configuration` chapter.

.. code-block:: YAML

    providers:
      LocalThredds:
        # minimal configuration requirements (where the real `THREDDS` service resides)
        # other optional parameters from `providers.cfg` can also be provided
        url: http://localhost:1234
        type: thredds

        # customizable request parsing methodology (specific to `thredds` type)
        configuration:
          # path prefix to skip (strip) before processing the rest of the path in case the
          # registered service URL in Magpie does not have the same root as proxied by Twitcher public URL
          skip_prefix: thredds
          # define which pattern matches that will map different path variations into same file resources
          # this can be used to consider two file extensions as the same resource to avoid duplication of permissions
          file_patterns:
            # note: make sure to employ quotes and double escapes to avoid parsing YAML error
            #       patterns are **NOT** UNIX filters, but regex format (eg: dot is 'any-character', not a literal dot)
            - ".*\\.nc"
          # path prefix to resources to be considered as BROWSE-able metadata (directory listing or file details)
          metadata_type:
            prefixes:
              - null  # note: special YAML value evaluated as `no-prefix`, use quotes if literal value is needed
              - "catalog\\.\\w+"  # note: special case for `THREDDS` top-level directory (root) accessed for `BROWSE`
              - catalog
              - ncml
              - uddc
              - iso
          # path prefix to resources to be considered as READ-able data (i.e.: file contents)
          data_type:
            prefixes:
              - fileServer
              - dodsC
              - dap4
              - wcs
              - wms
              - ncss/grid
              - ncss/point

..  warning:: Regular Expression Patterns

    Ensure to properly escape special characters, notably the dot (``.``), to avoid granting unexpected permissions that
    would match *any* character. Format employed in above patterns are traditional Regex, **not** UNIX style filters.

.. versionchanged:: 3.2
    Added ``catalog`` specific patterns by default to metadata prefixes that composes another valid URL variant to
    request :attr:`Permission.BROWSE` directly on the top-level `THREDDS`_ service (directory), although
    ``<prefix_type>`` is otherwise always expected at that second position path segment after the service name
    (see below example). The pattern allows multiple extensions to support the various representation modes of the
    ``catalog`` listing (e.g.: XML, HTML, etc.).

    As of that version, the ``prefixes`` entries also support patterns, using standard regular expression syntax.

.. versionchanged:: 3.3
    Added ``skip_prefix`` to allow ignoring intermediate path segments between the service name and the desired
    ``<prefix_type>`` position. A typical use case with `THREDDS`_ is the ``/thredds`` prefix it adds between its
    API entrypoint and `Tomcat` service running it. If this feature is not needed, it can be disabled by setting the
    parameter to ``null``.

.. versionchanged:: 4.1.2
    ``prefixes`` can now contain a ``/`` character. This allows `ServiceTHREDDS`_ to properly handle `THREDDS`_ services
    that have multiple path parts. For example, starting with `THREDDS`_ version 5, the ``ncss`` service contains two 
    sub-services which are accessed using the path prefixes ``ncss/grid`` and ``ncss/point``.  

Assuming a proxy intended to receive incoming requests configured with :class:`magpie.adapter.MagpieAdapter` such that
``{PROXY_URL}`` is the base path, the following path would point toward the registered service with the above YAML
configuration.

.. code-block:: http

    {PROXY_URL}/LocalThredds


An incoming request will be parsed according to configured values against the following format.

.. code-block:: http

    {PROXY_URL}/LocalThredds[/skip/prefix]/<prefix_type>/.../<file>

The above template demonstrates that `Magpie` will attempt to match the ``<prefix_type>`` part of the request path with
any of the listed ``prefixes`` in the configuration (*metadata* or *data*). The ``<prefix_type>`` location in the path
(i.e.: which segment to consider as ``<prefix_type>``) will be determined by the next part following configuration value
defined by ``skip_prefix`` (any number of sub-parts). If ``skip_prefix`` cannot be located in the request path or was
defined as ``null``, the first part after the service name is simply assumed as the ``<prefix_type>`` to lookup.

If a match is found between the various ``prefixes`` and ``<prefix_type>``, the corresponding *metadata* or *data*
content will be assumed, according to where the match entry was located, to determine whether the requested
:term:`Resource` should be validated respectively for :attr:`Permission.BROWSE` or :attr:`Permission.READ` access.
If no ``<prefix_type>`` can be resolved, the :term:`Permission` will be immediately assumed as :attr:`Access.DENY`
regardless of type. To allow top-level access directly on the :term:`Service`'s root without ``<prefix_type>``, it is
important to provide ``null`` within the desired ``prefixes`` list. Duplicates between the two lists of ``prefixes``
will favor entries in ``metadata_type`` over ``data_type``.

After resolution of the content type from ``<prefix_type>``, the resolution of any amount of
:class:`magpie.models.Directory` :term:`Resource` will be attempted. Any missing children directory :term:`Resource`
will terminate the lookup process immediately, and :term:`ACL` will be resolved considering :attr:`Scope.RECURSIVE` of
any applicable parent :term:`Resource` for the given :term:`Permission` selected by ``<prefix_type>`` and from where
lookup stopped.

Once the last element of the path is reached, the ``file_patterns`` will be applied against ``<file>`` in order to
attempt extracting the targeted :class:`magpie.models.File` :term:`Resource`. Patterns are applied until the first
positive match is found. Therefore, order is important if providing multiple patterns. For example, if the path ended
with ``file.ncml`` and, that both ``.*\\.ncml`` and ``.*\\.nc`` where defined in the configuration in that specific
order, the result will first match ``.*\\.ncml``, and the final :class:`magpie.models.File` :term:`Resource` value will
be considered as ``file.ncml`` for lookup. In this case, another request using only ``file.nc`` would lookup an entirely
different :term:`Resource`, since the second pattern would be the first successful match. On the other hand, if only
``.*\\.nc`` was defined in ``file_patterns``, the matched pattern would convert both the names ``file.ncml`` and
``file.nc`` to ``file.nc``, which will lookup exactly the same :class:`magpie.models.File` reference. The most common
usage of this feature is to support additional extension suffixes as the same file with regrouped permissions such that
``file.nc``, ``file.nc.ascii?``, ``file.nc.html``, etc. all correspond to single and common :term:`Resource`.

To summarize, if ``file_patterns`` produces a match, that matched portion will be used as lookup value of the
:term:`Resource`. Otherwise, if not any match could be found amongst all the ``file_patterns``, the plain ``<file>``
name is used directly (as is from the specified request path). The plain name is also used if ``file_patterns`` is
explicitly specified as an empty list or ``null``. Not explicitly overriding the field will result into using the
above *default* ``file_patterns``. The ``file_patterns`` allow for example to consider ``file.nc``, ``file.ncml`` and
``file.nc.html`` as the same :term:`Resource` internally, which avoids duplicating :term:`Applied Permission` across
multiple :term:`Resource` for their corresponding *metadata* or *data* representations.

ServiceWFS
~~~~~~~~~~~

.. seealso::
    - `ServiceGeoserverWFS`_ for a `GeoServer`_ flavoured implementation with only :term:`WFS` support.
    - Consider using `ServiceGeoserver`_ for multi-:term:`OWS` implementation support under a common
      endpoint representing a `GeoServer`_ instance.
    - https://www.ogc.org/standards/wfs (OpenGIS WFS 2.0.0 implementation)

This implementation is defined by :class:`magpie.services.ServiceWFS`.
It implements the original standard :term:`WFS` definition. There is **NO** concept of :class:`magpie.models.Workspace`
for this :term:`Service` implementation. Features are accessed directly using :class:`magpie.models.Layer` typed
:term:`Resources <Resource>`.

ServiceGeoserverWFS
~~~~~~~~~~~~~~~~~~~~~

.. seealso::

    - https://docs.geoserver.org/latest/en/user/services/wfs/reference.html
    - Consider using `ServiceGeoserver`_ for multi-:term:`OWS` implementation support under a common
      endpoint representing a `GeoServer`_ instance.

This implementation is defined by :class:`magpie.services.ServiceGeoserverWFS`.
It implements some extensions to base :term:`WFS` by providing more :term:`Permission` and scoping of
:class:`magpie.models.Layer` under :class:`magpie.models.Workspace` in a file-system-like fashion.

ServiceBaseWMS
~~~~~~~~~~~~~~~~~~~~~

.. seealso::

    Derived implementations:
    - :ref:`ServiceGeoserverWMS`
    - :ref:`ServiceNCWMS2`

This is a *partial base* class employed to represent :term:`OWS` `Web Map Service` extended via other complete classes.
It cannot be employed directly as :term:`Service` instance. The derived classes provide different parsing methodologies
and children :term:`Resource` representation according to their respective functionalities.

It provides support for the following permissions, each corresponding to the appropriate functionality of :term:`WMS`:

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

    - Base class: `ServiceBaseWMS`_
    - https://docs.geoserver.org/latest/en/user/services/wms/reference.html
    - Consider using `ServiceGeoserver`_ for multi-:term:`OWS` implementation support under a common
      endpoint representing a `GeoServer`_ instance.

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

    - Base class: `ServiceBaseWMS`_
    - https://reading-escience-centre.gitbooks.io/ncwms-user-guide/content/04-usage.html

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

.. seealso::
    Consider using `ServiceGeoserver`_ for multi-:term:`OWS` implementation support under a common
    endpoint representing a `GeoServer`_ instance.

The implementation of this :term:`Service` is handled by class :class:`magpie.services.ServiceWPS`. It is intended to
control access to the operations provided by an :term:`OWS` `Web Processing Service`. This :term:`Service` allows
one (1) type of child :term:`Resource`, namely the :class:`magpie.models.Process` which represent the execution units
that are registered under a remote `WPS`. Every :class:`magpie.models.Process` cannot itself have a child
:term:`Resource`, making :ref:`ServiceWPS` maximally a 2-tier level hierarchy.

There are three (3) types of :term:`Allowed Permission` which each represent an operation that can be requested from it
(via ``request`` query parameter value of the HTTP request), specifically the :attr:`Permission.GET_CAPABILITIES`,
:attr:`Permission.DESCRIBE_PROCESS`, and :attr:`Permission.EXECUTE`. The :attr:`Permission.GET_CAPABILITIES`
corresponds to the retrieval of available list of *Processes* on the `WPS` instance, and therefore, can only be applied
on the top-level :term:`Service`. The other two permissions can be applied on either the :term:`Service` or specifically
on individual :class:`magpie.models.Process` :term:`Resource` definitions. When applied to the :term:`Service` with
:attr:`Scope.RECURSIVE` modifier, the corresponding :term:`Permission` becomes effective to all underlying *Processes*.
Otherwise, the :term:`Permission` applied on specific :class:`magpie.models.Process` entries control the specific
:term:`ACL` only for it. When a specific :term:`Permission` is involved on a :class:`magpie.models.Process` during
:term:`Effective Permission` resolution, the value of the query parameter ``identifier`` is employ to attempt mapping
it against an existing :term:`Resource`. The resolution of :term:`Effective Permissions <Effective Permission>` in the
event of multi-level tree :term:`Resource` is computed in the usual manner described in the :ref:`Permissions` chapter.


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


ServiceGeoserverWPS
~~~~~~~~~~~~~~~~~~~~~~~

.. seealso::
    Consider using `ServiceGeoserver`_ for multi-:term:`OWS` implementation support under a common
    endpoint representing a `GeoServer`_ instance.

The implementation of this :term:`Service` is handled by class :class:`magpie.services.ServiceGeoserverWPS`.
It offers similar operations and request handling to :ref:`ServiceWPS`, but adds scoped :class:`magpie.models.Workspace`
definition of :class:`magpie.models.Process` as for other `GeoServer`_ base :term:`Services <Service>`, in order to
properly parse request paths that include such references. Other than the :term:`Resource` hierarchy being nested by
:class:`magpie.models.Workspace`, the rest of the parsing and handling methodology is equivalent to :ref:`ServiceWPS`.


ServiceGeoserver
~~~~~~~~~~~~~~~~

.. versionadded:: 3.21

.. seealso::
    - :ref:`ServiceGeoserverWFS`
    - :ref:`ServiceGeoserverWMS`
    - :ref:`ServiceGeoserverWPS`

This :term:`Service` is combined :term:`OWS` implementation for `GeoServer`_ that allows simultaneous representation of
:term:`WFS`, :term:`WMS` and :term:`WPS` :term:`Resources <Resource>` all nested under a single reference hosted under
common remote URL. Using this implementation, :class:`magpie.models.Workspace` are first required as immediate children
under the root :term:`Service`, and can be followed by both :term:`Resources <Resource>` of type
:class:`magpie.models.Layer` and :class:`magpie.models.Process`.
There are two main advantages of using this combined implementation over their specific :term:`OWS` counterparts.

First, using the same :term:`Resources <Resource>` to represent corresponding elements in the `GeoServer`_ across
:term:`OWS` endpoints reduces the chances of inconsistent access to otherwise equivalent :term:`Resources <Resource>`.
For example, a :class:`magpie.models.Layer` that is granted :term:`Permission` to retrieve features (:term:`WFS`) or
to render their map raster (:term:`WMS`) will be managed using the same reference. Using distinct
:ref:`ServiceGeoserverWFS` and :ref:`ServiceGeoserverWMS` :term:`Service` in `Magpie` would require from to
administrator to always maintain their :term:`Permissions <Permission>` in sync. This is prone to many errors and
confusion when managing multiple large hierarchies of layers.

Second, this :ref:`ServiceGeoserver` implementation is *configurable*. In other words, if the :term:`Service`
administrator intends to only make use (for the moment) of :term:`WFS` functionality, they can customize this
:term:`Service` using the following definition.

.. code-block:: YAML

    providers:
      RemoteGeoServer:
        # minimal configuration requirements (where the real `GeoSever` service resides)
        # other optional parameters from `providers.cfg` can also be provided
        url: http://localhost:1234
        type: geoserver

        # customizable configuration (enable desired OWS/REST request handlers)
        # all OWS/REST services are enabled by default if no configuration is provided
        configuration:
          wfs: true
          wms: false
          wps: false
          api: false

This would make sure that request parsing and access to :term:`WMS`, :term:`WPS` and any REST :term:`API` endpoints
are disabled, but leaves the :term:`Resource` definitions available for use at a later time if the administrator
decides to eventually make use of them.
For example, the administrator could decide to start using :term:`WMS` as well without any further change
needed other than updating this :term:`Service` custom configuration and applying :term:`Permissions <Permission>`
specific only to :term:`WMS`.
All other :term:`Applied Permissions <Applied Permission>` to existing :term:`User`, :term:`Group` and :term:`Resource`
for that :term:`Service`, as well as their full :term:`Resource` tree hierarchy, would be automatically ported from
the :term:`WFS` to :term:`WMS` request handlers.

.. note::
    Custom configuration can be provided With either the `providers.cfg`_ (as presented above), in
    a :ref:`config_file` as described in greater lengths within the :ref:`configuration` chapter,
    or by providing the ``configuration`` field directly within the :term:`API` request body during
    :term:`Service` creation.


Service Synchronization
------------------------

.. versionadded:: 0.7

Some :term:`Service` implementations offer a synchronization feature which is represented by field ``sync_type`` within
`Magpie` API responses. When this parameter is defined (during :term:`Service` creation, whether through API request or
startup :ref:`Configuration`), the corresponding :term:`Service` will be able to query the real
*remote service provider* to retrieve actual :term:`Resource` nested under it, based on the referenced implementation
from the :mod:`magpie.cli.sync_services` module. Each of these synchronization implementations must derive from
:class:`magpie.cli.sync_service.SyncServiceInterface` and must populate the database with appropriate :term:`Resource`
types. This allows quick generation of the retrieved :term:`Resource` tree hierarchy rather than manually creating each
element.

.. note::
    The depth of the :term:`Resource` tree hierarchy that will be synchronized between `Magpie` and the
    *remote service provider* depends on the specific implementation of the ``sync_type`` referring to a derived
    :class:`magpie.cli.sync_service.SyncServiceInterface`. These classes provide a parameter ``max_depth`` which
    can limit how many :term:`Resource` must be generated. This is useful for entries that have very large and deeply
    nested structure that would take too long to synchronize. By default, ``max_depth`` is not set to pull the whole
    tree hierarchy.

.. note::
    If only :attr:`Scope.RECURSIVE` :term:`Permission` are being applied on the :term:`Service` or their children
    :term:`Resource`, it is better to enter *fewer* children element in the tree to reduce computation time of
    :term:`Effective Permissions <Effective Permission>`. The complete hierarchy should be employed only when the depth
    of the tree is relatively shallow or that :attr:`Scope.MATCH` must be applied specifically for some :term:`Resource`
    to obtain desired access behaviour.

When using the `Magpie` Docker image, the default command run the `magpie-cron`_ utility in parallel to the API. This
cron job will periodically execute the :term:`Resource` auto-synchronization feature for a given :term:`Service` that
supports it.

The synchronization mechanism can be launched from `Magpie` UI using the ``Sync`` button located on relevant pages.

.. seealso::

    Utility ``magpie_sync_resources`` in :ref:`cli_helpers` is also available to manually launch a
    :term:`Resource` synchronization operation from the command line for supporting :term:`Service`-types.
    This is the same operation that gets executed by `magpie-cron`_.
