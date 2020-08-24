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

Most of the HTTP routes require by default administrative privileges. Exceptions to this are notably the requests
with :term:`User`-scoped routes under ``/users/{user_name}`` which allow retrieval of :term:`Public` :term:`Resource`
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

In order to achieve publicly accessible :term:`Service` or :term:`Resource` functionality by any given individual, the
desired :term:`Permission` must be applied on special :term:`Group` defined with configuration setting
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_GROUP`. Since every existing :term:`User` automatically gets attributed
membership to that special :term:`Group` at creation time, all applied :term:`Permission` to it are inherited by
everyone, making the corresponding :term:`Resource` effectively :term:`Public`.

Note that it is **VERY** important to apply :term:`Permission` on the :term:`Group` defined by
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_GROUP` rather than then :term:`User` defined by
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` in order to achieve :term:`Public`-like access by everyone. This is
because using the :term:`User` instead of the :term:`Group` would instead make the :term:`Resource`
accessible **ONLY** while not authenticated (i.e.: when :term:`Logged User` corresponds to
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`). Once a real :term:`User` would authenticate itself, they would
suddenly *lose* the :term:`Public` :term:`Permission` since :term:`Logged User` would not be the special :term:`User`
anymore. That would lead to unexpected behavior where :term:`Resource` intended to be always :term:`Public` would
contextually change access criteria depending on active :term:`Logged User` session.

Special user :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` is available only for evaluation purpose of
:term:`Public`-only :term:`Permission` applied to :term:`Service` and :term:`Resource`, but is technically not required
to execute `Magpie` application. Effectively, when the active session corresponds to unauthenticated
:term:`Logged User`, it is still allowed to call :term:`User`-scoped API request paths, which will return details about
:term:`Public` accessible items.

.. _perm_example:
.. |perm_example| replace:: Permission Example
Example to distinguish Applied, Inherited and Effective Permissions
--------------------------------------------------------------------------------------

This section intends to provide more insight on the different :ref:`Types of Permissions` using a simplified
demonstration of interaction between defined :term:`Service`, :term:`Resource`, :term:`Group`, :term:`User` and
:term:`Permission` elements.

Let's say we have some fictive :term:`Service` that allows the following *permission scheme*, and that it implements
the default hierarchical resolution of :term:`Resource` items (i.e.: having permissions on ``resource-type-1`` also
provides the same ones for child resources ``resource-type-2``).

.. code-block::

    service-type                [read | write]
        resource-type-1         [read | write]
            resource-type-2     [read | write]

Given that scheme, let's say that existing elements are defined using the allowed types as follows:

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
    (service-3,   example-user,  write)
    (resource-B1, example-group, read)

For simplification purposes, we will use the names directly in following steps, but remember that requests would
normally require unique identifiers for :term:`Resource` resolution. Lets observe what happens using different query
parameters with request ``GET /users/{user_name}/resources/{resource_id}/permissions``.

If no query parameter is specified, we obtain permissions as follows:

.. code-block::

    /users/example-user/resources/service-1/permissions                     => [write]
    /users/example-user/resources/service-2/permissions                     => []
    /users/example-user/resources/resource-A/permissions                    => [read]
    /users/example-user/resources/service-3/permissions                     => [write]
    /users/example-user/resources/resource-B1/permissions                   => []
    /users/example-user/resources/resource-B2/permissions                   => []

Using ``inherited`` option, we obtain the following:

.. code-block::

    /users/example-user/resources/service-1/permissions?inherited=true      => [write]
    /users/example-user/resources/service-2/permissions?inherited=true      => [write]  :sup:`(1)`
    /users/example-user/resources/resource-A/permissions?inherited=true     => [read]
    /users/example-user/resources/service-3/permissions?inherited=true      => [write]
    /users/example-user/resources/resource-B1/permissions?inherited=true    => [read]   :sup:`(1)`
    /users/example-user/resources/resource-B2/permissions?inherited=true    => []

As illustrated, requesting for `inherited permissions`_ now also returns :term:`Group`-related :term:`Permission`
:sup:`(1)` where they where not returned before with only :term:`User`-related :term:`Permission`.

On the other hand, using ``effective`` would result in the following:

.. code-block::

    /users/example-user/resources/service-1/permissions?effective=true      => [write]
    /users/example-user/resources/service-2/permissions?effective=true      => [write]          :sup:`(2)`
    /users/example-user/resources/resource-A/permissions?effective=true     => [read, write]    :sup:`(3)`
    /users/example-user/resources/service-3/permissions?inherited=true      => []
    /users/example-user/resources/resource-B1/permissions?effective=true    => [read]           :sup:`(2)`
    /users/example-user/resources/resource-B2/permissions?effective=true    => [read, write]    :sup:`(4)`

In this case, :term:`Resource`s that had :term:`Permission` directly set on them :sup:`(2)`, whether through
:term:`User` or :term:`Group` combination, all return the exact same set of :term:`Permission`. This is because
`effective permissions`_ always imply `inherited permissions`_ (i.e.: using both query simultaneously is redundant).
The reason why we obtain these sets for cases :sup:`(2)` is also because there is no other :term:`Permission` applied
to any of their parent :term:`Service` or :term:`Resource`. Contrarily, ``resource-A`` :sup:`(3)` now additionally
receives :term:`Permission` ``read`` indirectly from its parent ``service-2`` (note: ``write`` is redundant here).
Similarly, ``resource-B2`` :sup:`(4)` which did not even have any immediate :term:`Permission` applied to it,
now receives both ``read`` and ``write`` access, respectively from its parents ``resource-B1`` and ``service-3``. This
demonstrates why, although `effective permissions`_ imply `inherited permissions`_, they do not necessarily resolve to
the same result according to the effective :term:`Resource` hierarchy and its parent-children resolution implementation.

Using ``effective`` query tells `Magpie` to rewind the :term:`Resource` tree from the requested :term:`Resource` up to
the top-most :term:`Service` in order to accumulate all `inherited permissions`_ observed along the way for every
encountered element. All :term:`Permission` that is applied *higher* to the requested :term:`Resource` are considered
as if applied directly on it. Query ``inherited`` limits itself only to the specifically requested :term:`Resource`,
without hierarchy resolution, but still considering :term:`Group` memberships. For this reason, ``inherited`` *could*
look the same to ``effective`` results if the :term:`Service` hierarchy is "flat", or if all :term:`Permission` can be
found directly on the target :term:`Resource`, but it is not guaranteed. This is further important if the
:term:`Service`'s type implementation provides custom methodology for parsing the hierarchy resolution (see
:ref:`services` for more details).

In summary, ``effective`` tells us *"which permissions does the user have access to for this resource"*, while
``inherited`` answers *"which permissions does the user have on this resource alone"*, and without any query, we
obtain *"what are the permissions that this user explicitly has on this resource"*.


Finding User Permissions
----------------------------

One of the trickiest (and often annoying) situation when we want to figure out which :term:`Service` a :term:`User` has
any :term:`Permission` on, is where to start looking. Effectively, if we have a vast amount of registered
:term:`Service` each with a immense hierarchy of :term:`Resource`, doing an exhaustive search can be quite daunting,
not to mention costly in terms of request lookup and resources.

For this purpose, there is one query parameter named ``cascade`` that can be employed with request
``GET /users/{user_name}/services``. In normal condition (without the parameter), this request responds with every
:term:`Service` where the user has `direct permissions`_ on. With the added query parameter, it tells `Magpie` to
recursively search the hierarchy of `effective permissions`_ and return all :term:`Service` instances that possess
*any* :term:`Permission` applied to at least one child :term:`Resource` at *any* level.

This query can be extremely useful to quickly answer *"does the user have any permission at all on this service"*,
without needing to manually execute multiple successive lookup requests with all combinations of :term:`Resource`
identifiers in the hierarchy.
