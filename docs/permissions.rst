.. _permissions:
.. include:: references.rst

===========
Permissions
===========

Types of Permissions
-----------------------

Across the documentation and the code, term :term:`Permission` is often employed interchangeably to represent different
more subtle contextual functionalities. This is mostly an abuse of language, but is preserved regardless in order to
maintain backward compatibility of features and API response content with older systems that could employ `Magpie`.
Therefore, care must be taken to consider under which context this term is observed to ensure one correctly interprets
the results.

More specifically, following distinction can be considered between different kind of :term:`Permission` used by
`Magpie`:

.. _applied permissions:
- **Applied Permissions**:
    Represents a "rule" which defines a combination of ``(User|Group, Service|Resource, Permission)``.
    These entries are parsed during requests to determine which access rights will be granted or denied for the
    respective :term:`User`.

.. _direct permissions:
- **Direct Permissions**:
    Represents a "rule" combination that was explicitly applied to a :term:`Service`. Rules applied to children
    :term:`Resource` are **NOT** considered :term:`Direct Permission` (they are simply `applied permissions`_ without
    any special connotation. :term:`Direct Permission` are retrieved from the :term:`Service` definition while others
    are obtained from corresponding :term:`Resource` permissions allowed under this :term:`Service`. The actual values
    extracted in each case are purely dependant of the :term:`Service`'s implementation, as each :term:`Service` is
    only a specialized :term:`Resource`.

.. _inherited permissions:
- **Inherited Permissions**:
    Represents the combined set of `applied permissions`_ for a :term:`User` and every one of its :term:`Group`
    memberships. When requesting :term:`Group` permissions, only "rules" explicitly set on the given group are returned.
    The same concept applies when *only* requesting :term:`User` permissions. Providing applicable :term:`User`-scoped
    requests with ``inherit=true`` query parameter will return the *merged* set of `applied permissions`_ for that
    :term:`User` and all his :term:`Group` membership. See `perm_example`_ for complete comparison.

.. _effective permissions:
- **Effective Permissions**:
    Represents all `applied permissions`_ of the :term:`User` and all :term:`Group` membership, as well as the
    extensive resolution of the :term:`Service` and every children :term:`Resource` in its hierarchy. Effective
    permissions automatically imply ``inherit=True``, and can be obtained from :term:`User`-scoped requests with
    ``effective=true`` query parameter wherever supported. See `perm_example`_ for complete comparison.

.. _access permissions:
- **Access Permissions**:
    Represents the required level of :term:`Permission` needed to access `Magpie` API routes to request details. These
    can be referred to as "roles", but are inferred by :term:`Group` memberships of the :term:`Logged User` attempting
    to complete the request. See `Route Access`_ details.

.. following are potential but not implemented:
ownership permissions:
    user/group that owns the service/resource
    defined with the id saved directly under that Resource (see Resource.owner_[user|group]_id)
role permission:
    (user|group, permission) relationship, within separate tables in database
    maybe could be combined used with group permissions and 'access permissions' do, but there
    is still a need to check view access dynamic group with them, might require some GroupFactory?


Route Access
-------------

Most of the HTTP routes require by default administrative privileges. Exceptions to this are
notably the requests :term:`User`-scoped routes under ``/users/{user_name}`` which allow retrieval of :term:`Public`
details, and informational API routes that are granted full access to anyone such as the `Magpie REST API`_
documentation served under a running `Magpie` instance.

.. versionchanged:: 2.0.0

Some routes under ``/users/{user_name}`` are also granted more *contextual access* to self-referencing users using
:py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION`. In other words, if the :term:`Logged User` corresponds to the
path variable :term:`User`, access is also granted to allow that individual to obtain or update its own details.

Typically, request `access permissions`_ fall into one of the following category for all API endpoints. Higher
permissions in the table imply higher access.

.. list-table::
    :header-rows: 1

    * - Permission
      - Request Requirement
    * - :py:data:`magpie.constants.MAGPIE_ADMIN_PERMISSION`
      - :term:`Logged User` must be a member of :term:`Group` configured by
        :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP`.
    * - :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION`
      - :term:`Logged User` must at the very refer to itself in the request path variable.
    * - :py:data:`pyramid.security.Authenticated`
      - :term:`Logged User` must at the very least be :term:`Authenticated`.
    * - :py:data:`pyramid.security.NO_PERMISSION_REQUIRED`
      - Anyone can access the endpoint, including unauthenticated :term:`User` session.

When targeting specific :term:`User`-scoped routes, the following (simplified) operations are applied to determine if
access should be granted to execute the request:

1. :term:`Logged User` has administrative-level `access permissions`_ (always granted access).
2. :term:`Logged User` corresponds exactly to same :term:`User` identified from the path variable's value.
3. :term:`User` in path variable is the special keyword :py:data:`magpie.constants.MAGPIE_LOGGED_USER`.
4. :term:`User` in path variable is special user :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`.
5. For the first matched of the above steps, the condition is compared to the specific request requirement.
   Access is granted or denied according to met condition result.

.. note::
    Whenever one of the :term:`User`-scoped requests refers to specials keywords such as
    :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` or :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP`, any operation
    that has the intention to modify the corresponding :term:`User` or :term:`Group` are forbidden. There is therefore
    some additional request-specific logic (depending on its purpose and resulting actions) for special-cases that is
    not explicitly detailed in above steps. Some of these special behaviors can be observed across the various `tests`_.

.. _tests: https://github.com/Ouranosinc/Magpie/tree/master/tests


Public Access
-------------

In order to achieve publicly accessible :term:`Service` or :term:`Resource` by any given individual, the applicable
:term:`Permission` must be applied on special :term:`Group` defined with configuration setting
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_GROUP`.

When the path variable matches the special keyword of the :term:`Logged User`, the special :term:`User` defined by
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` is also allowed to return corresponding details. Since this includes
unauthenticated use-case, :py:data:`NO_PERMISSION_REQUIRED` must be used.

for  , making every existing :term:`User` automatically receiving the effective :term:`Permission`, including even unauthenticated sessions

.. _perm_example:
.. |perm_example| replace:: Permission Example
Example to distinguish Applied, Inherited and Effective Permissions
--------------------------------------------------------------------------------------

Let's say we have some fictive :term:`Service` that allows the following *permission scheme*, and that it implements
the default hierarchical resolution of :term:`Resource` items (i.e.: having permissions on ``resource-type-1`` also
provides the same ones for child resources ``resource-type-2``).

.. code-block::

    service-type                [read | write]
        resource-type-1         [read | write]
            resource-type-2     [read | write]

Given that scheme, let's say that existing elements are defined as follows:

.. code-block::

    service-1               (service-type)
    service-2               (service-type)
        resource-A          (resource-type-1)
    service-3               (service-type)
        resource-B1         (resource-type-1)
            resource-B2     (resource-type-2)

Let's says we also got a ``example-user`` that is member of ``example-group``, and that  `applied permissions`_ on them
are as follows:

.. code-block::

    (service-1,   example-user,  write)
    (service-2,   example-group, write)
    (resource-A,  example-user,  read)
    (resource-B2, example-user,  write)
    (resource-B1, example-group, read)

For simplification purposes, we will use the names directly in following steps, but remember that requests would
normally require unique identifiers for :term:`Resource` resolution. Lets observe what happens using different query
parameters with request ``GET /users/{usr}/resources/{id}/permissions``.

If no query parameter is specified, we obtain permissions as follows:

.. code-block::

    /users/example-user/resources/service-1/permissions     => [write]


Using ``inherited`` option, we obtain the following:

.. code-block::

    /users/example-user/resources/service-1/permissions     => [write]


Using the query parameter in `/users/{usr}/resources/{id}/permissions?effective=true` allows to obtain the effective permission of that specific user/resource combination including permissions group permissions the user is member of.

Although both `inherit` and `effective` flag consider the permissions of groups the user is part of, the `effective` flag goes an extra step to rewind up to the service any permissions that apply to children resources, while `inherit` with only resolve the user & group permissions of the specific resource. This means that a recursive-permission placed on a parent resource at higher level than the current resource will be shown by `effective` but not by `inherit` as the permission is not set directly on that resource.

    For a "flat" :term:`Service`, this is completely equivalent to `inherited permissions`_ as there are effectively
    no hierarchy to resolve. Default implementation for :term:`Service`-types that support "tree" hierarchy is to
    rewind the targeted child :term:`Resource` up to the containing :term:`Service` in order to cumulate any parent
    :term:`Permission` that should be inherited by all sub-nodes. Each :term:`Service` can implement its own parsing
    methodology according to desired its functionality. Please refer to :ref:`services` for details about each type's
    implementation.



Another special query parameter ``cascade`` is also available on route ``GET /users/{usr}/services``.
This option allows to recursively search all children :term:`Resource` under the :term:`Service`
