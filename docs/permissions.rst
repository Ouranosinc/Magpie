.. include:: references.rst

.. default location to quickly reference items without the explicit and long prefix
.. using the full name when introducing the element (to make the location obvious), then reuse shorthand variant
.. py:currentmodule:: magpie.permissions

.. _permissions:

Permissions
===========

This chapter describes the various :term:`Permission` types, format representation, and usage.
For details regarding :term:`Authentication`, please refer to :ref:`auth_methods` instead.

.. _permission_types:

Types of Permissions
-----------------------

Across the documentation and the code, term :term:`Permission` is often employed interchangeably to represent different
and more subtle contextual functionalities. This is mostly an abuse of language, but is preserved regardless in order
to maintain backward compatibility of features and API response content with older systems that could employ `Magpie`.
Therefore, care must be taken to consider under which context this term is employed to ensure correct interpretation
of observed results.

.. versionchanged:: 3.0
    Following introduction of :ref:`Permission Representations` as JSON objects with this version, a new
    :class:`magpie.permissions.PermissionType` enum was added to make following types more explicit. Responses from
    the API will include a |perm_type|_ field that indicates precisely the type of :term:`Permission` returned, for each
    specific item presented below.

.. seealso::
    - `Permissions Representation`_
    - |perm_example_type|_

More specifically, following distinctions and terminology can be observed between different kind of :term:`Permission`
employed by `Magpie`:

.. _allowed_permissions:
.. |allowed_permissions| replace:: Allowed Permissions

- **Allowed Permissions**:
    Represents the set of valid :term:`Permission` values that *could* be applied to a given :term:`Service` or
    :term:`Resource`, depending on their type's implementation. Every allowed :term:`Permission` is one entry from
    :py:data:`magpie.permissions.Permission`, and their set define the *schema* that will pass validation if applied
    to corresponding items of :py:mod:`magpie.services`, but they are not necessarily an active nor existing entry
    in the database (i.e.: |applied_permissions|_). In general, these values are obtained from requests scoped under
    paths ``/service`` and ``/resources``.

.. _applied_permissions:
.. |applied_permissions| replace:: Applied Permissions

- **Applied Permissions**:
    Represents an active "rule" which defines a combination of ``(User|Group, Service|Resource, Permission)``.
    These entries are validated during requests against the appropriate |allowed_permissions|_ of the targeted item
    (:term:`Service` or :term:`Resource`) to create the "rule" under (for) the targeted :term:`User` or :term:`Group`.
    When executing requests under scopes ``/users`` and ``/groups``, responses without query parameter modifiers
    are by default |applied_permissions|_. These are also scoped under a *single context* at a given time
    (:term:`User` or :term:`Group`), depending on the request path being executed. They determine
    which access rights will be granted or denied for the respective :term:`User` or :term:`Group`.

.. _direct_permissions:
.. |direct_permissions| replace:: Direct Permissions

- **Direct Permissions**:
    Explicitly represents |applied_permissions|_ "rules" in the case of :term:`User` context, which is, when
    :term:`Group` membership are **NOT** considered (i.e.: |inherited_permissions|_). Since calling ``/users``
    scoped requests can lead to all different :term:`Permission` variations presented here with different contextual
    information, this term is employed to specifically indicate the situations of the default behaviour of the routes
    without query parameters.

.. _immediate_permissions:
.. |immediate_permissions| replace:: Immediate Permissions

- **Immediate Permissions**:
    Represents a "rule" combination that was explicitly applied to a :term:`Service`. Rules applied to children
    :term:`Resource` are **NOT** considered |immediate_permissions|_ (they are simply |applied_permissions|_
    without any special connotation). Note that |immediate_permissions|_ are still |applied_permissions|_.
    They are a special subset of |applied_permissions|_ matching how :term:`Service` are a specialized implementation
    of :term:`Resource` (see: :class:`magpie.models.Service`). This kind of :term:`Permission` is notably referred
    to by requests for `Finding User Permissions`_ as they provide useful and unique properties.

.. _inherited_permissions:
.. |inherited_permissions| replace:: Inherited Permissions

- **Inherited Permissions**:
    Represents the combined set of |applied_permissions|_ from the :term:`User` context and every one of its
    :term:`Group` membership contexts. When requesting a :term:`Group`'s permissions, only "rules" explicitly set on
    the given group are returned. The same concept applies when *only* requesting :term:`User` permissions. Providing
    applicable :term:`User`-scoped requests with ``inherited=true`` query parameter will return the complete set of
    |applied_permissions|_ for that :term:`User` and all his :term:`Group` membership simultaneously.
    See |perm_example_type|_ for comparison of results with different query parameters.

    .. versionchanged:: 2.0
        Prior to this version, ``inherit`` (without ``ed``) was employed as query parameter name. This often lead to
        confusion between expected and returned results due to mistakenly employed adjective. Because they are referred
        to as |inherited_permissions|_ in the documentation and naturally from a linguistic standpoint, query
        ``inherited`` (with ``ed``) is now the *official* parameter. The older variant remains supported and equivalent.

.. _resolved_permissions:
.. |resolved_permissions| replace:: Resolved Permissions

- **Resolved Permissions**:
    Specific interpretation of |inherited_permissions|_ when there are multiple |applied_permissions|_
    combinations to the :term:`User` and/or his :term:`Group` memberships. The *resolution* of all those definitions
    are interpreted on a per-:term:`Resource` basis to obtain an equivalent and unique :term:`Permission` matching
    the one with highest priority, only for that localized scope. This resulting *resolved* :term:`Permission` reduces
    the set of defined |inherited_permissions|_ such that other entries on the same :term:`Resource` can be
    ignored as they are either redundant or conflicting but of lesser priority. The resolution considers the various
    priorities according to their associated :term:`User`, :term:`Group`, :class:`Access` and :class:`Scope` attributes.
    See `Extended Representation`_ section for details.

    .. versionadded:: 3.5
        The concept did not exist before this version as every :term:`Group` was considered equal, whether they were
        with a *special* connotation (e.g.: :envvar:`MAGPIE_ANONYMOUS_GROUP`) or any other *generic* :term:`Group`.

.. _effective_permissions:
.. |effective_permissions| replace:: Effective Permissions

- **Effective Permissions**:
    Represents all |resolved_permissions|_ of the :term:`User` and all its :term:`Group` membership, as well as the
    extensive resolution of the :term:`Service` and every children :term:`Resource` in its hierarchy for the requested
    :term:`Resource` scope. Effective permissions automatically imply ``inherited=True`` and ``resolved=True``, and can
    be obtained only from :term:`User`-scoped requests with ``effective=true`` query parameter wherever supported.
    See |perm_example_type|_ for complete comparison.

.. _access_permissions:
.. |access_permissions| replace:: Access Permissions

- **Access Permissions**:
    Represents the required level of :term:`Permission` needed to access `Magpie` API routes to request details. These
    can be referred to as "roles", but are inferred by :term:`Group` memberships of the :term:`Logged User` attempting
    to complete the request. It is the only kind of :term:`Permission` which the values are not retrieved from the
    enum :class:`magpie.permissions.Permission`, but rather from a combination of *special* :term:`Group` and
    :ref:`Configuration` constants. See `Route Access`_ for more details.

.. todo: (?) resource owner permission?
.. todo: (?) role permission to access different API requests/sections by user-context
.. following are potential but not implemented / unused:
    !! also add appropriately in other parts of the doc such as "type" field
    ownership permissions:
        user/group that owns the service/resource
        defined with the id saved directly under that Resource (see Resource.owner_[user|group]_id)
    role permission:
        (user|group, permission) relationship, within separate tables in database
        maybe could be combined used with group permissions and 'access permissions' do, but there
        is still a need to check view access dynamic group with them, might require some GroupFactory?

.. _perm_route_access:

Route Access
-------------

Most of the HTTP routes require by default administrative privileges (i.e.: :envvar:`MAGPIE_ADMIN_PERMISSION` or
equivalent inferred from :envvar:`MAGPIE_ADMIN_GROUP` membership for the :term:`Logged User`). Exceptions to this are
notably requests with :term:`User`-scoped routes under ``/users/{user_name}`` which allow retrieval of :term:`Public`
:term:`Resource` details (e.g.: obtaining information about what :envvar:`MAGPIE_ANONYMOUS_GROUP` members have
access to), and informative API routes that are granted :ref:`Public Access` to anyone such as the `Magpie REST API`_
documentation served under a running `Magpie` instance or the instance's version route.

.. versionchanged:: 2.0

    Some routes under ``/users/{user_name}`` are also granted more *contextual access* than the default admin-only
    access requirement to allow self-referencing :term:`User` operations. Using a combination of view configurations
    with :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` and :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION`,
    the permitted functionalities are controlled according to the actual procedure being executed. In other words, if
    the :term:`Request User` corresponds to the path variable :term:`Context User`, access *could* also be granted to
    allow that individual to obtain or update its own details.
    In this situation, allowed routes are controlled on a per-request basis for the respective contextual
    operations accomplished by each request. For example, :term:`Logged User` could be granted access to update its
    account details, but won't be able to grant itself more permissions on a given :term:`Service` or :term:`Resource`.

Typically, request |access_permissions|_ fall into one of the following categories for all API endpoints.
Permissions listed in the table typically imply descending access conditions, the first being the most restrictive
access (or requiring the highest privileges), and the last being more permissive to the open public.

.. |request_access_table| replace:: Request Access Conditions
.. list-table:: |request_access_table|
    :name: request_access_table
    :header-rows: 1

    * - View Permission
      - Request Requirement
    * - :py:data:`magpie.constants.MAGPIE_ADMIN_PERMISSION`
      - :term:`Logged User` must be a member of :term:`Group` configured by
        :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP`.
    * - :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION`
      - :term:`Logged User` must at the very least refer to itself in the request path variable and **MUST**
        be authenticated with an active session.
    * - :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION`
      - :term:`Request User` must refer to itself as :term:`Context User`, but **CAN** be authenticated or not.
    * - :py:data:`pyramid.security.Authenticated`
      - :term:`Logged User` must at the very least be :term:`Authenticated`, but **CAN** refer to any other
        :term:`Context User` or even none at all.
    * - :py:data:`pyramid.security.NO_PERMISSION_REQUIRED`
      - Anyone can access the endpoint (i.e.: :ref:`Public Access`), including unauthenticated
        :term:`Request User` session.

When targeting specific :term:`User`-scoped routes, the following (simplified) operations are applied to determine if
access should be granted to execute the request:

1. verify if :term:`Logged User` has administrative-level |access_permissions|_ (always granted access).
2. verify if :term:`Context User` corresponds exactly to same :term:`Request User` identified from the path variable.
3. verify if :term:`Context User` in path variable is *special* keyword :py:data:`magpie.constants.MAGPIE_LOGGED_USER`.
4. verify if :term:`Context User` in path variable is *special* user :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`.

For the first matched of the above steps, the condition is compared to the specific request requirement.
Access is granted or denied respectively to met or insufficient privileges against the |request_access_table|_ table.

Every time a :term:`User`-scoped request is executed, the targeted :term:`Context User` is resolved accordingly to
either the explicit ``{user_name}`` value provided, or the auto-resolved :py:data:`magpie.constants.MAGPIE_LOGGED_USER`
value that implicitly retrieves the :term:`Request User` as equal to the :term:`Context User`.

.. note::
    Whenever one of the :term:`User`-scoped requests refers to specials keywords such as
    :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` or :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP`, any operation
    that has the intention to modify the corresponding :term:`User` or :term:`Group` are forbidden. There is therefore
    some additional request-specific logic (depending on its purpose and resulting actions) for special cases that are
    not explicitly detailed in above steps. Some of these special behaviors can be observed across the various `tests`_.


Finally, it is worth further detailing the small distinction between
:py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` and :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION`,
provided that they act almost the same way. More precisely, they both work in the exact situation where
:term:`Request User` is equal to :term:`Context User`, but each for different sets of applicable values for those
:term:`User` references.

When a route is attributed with :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` access requirement, it means that
the :term:`Request User` must absolutely be authenticated (i.e.: not ``None``) to be granted access, while
:py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION` does not specifically enforce this criteria. The *contextual*
permission is an extended set of the *logged* one with two exceptions, which are when the :term:`Request User` is
unauthenticated and/or when the referenced :term:`Context User` is resolved as the *special* :term:`User` defined
by :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` that also represents unauthenticated :term:`User`.

An example where such distinction is important goes as follows. A request that requires to update :term:`User`
details *minimally* requires a :term:`Logged User` because it does not make sense to attempt modification
of an undefined :term:`User`. If the :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION` requirement was applied, it
would imply that unauthenticated *special* :term:`Context User` *could* update itself, which is obviously wrong since
it does not represent a *real* :term:`User` account. On the other hand, it makes sense to allow some
:term:`Request User` to update its personal details. In this case, the applicable view configuration should be
:py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` so that it immediately forbids the operation if
the :term:`Request User` did not accomplish prior :term:`Authentication`. As counter example, requesting details about
resources that are :term:`Public` (more details in :ref:`Public Access` for this), makes sense even when we did not
complete prior :term:`Authentication`, as they are accessible to everyone. The view configuration in this case should
employ :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION` so that :term:`Context User` referring to unauthenticated
:term:`User` will be permitted. For previous cases, |access_permissions|_ cannot be defined using
:py:data:`pyramid.security.Authenticated`, as this would enforce requirement to login first (when not always needed),
while :py:data:`pyramid.security.NO_PERMISSION_REQUIRED` would fully open *all* requests, including ones targeting
for example an administrator as :term:`Context User` which should be masked to non-administrators.

For all presented reasons above, it is important to distinguish between |access_permissions|_ applied to request
view configuration and |applied_permissions|_ on resources, and they conceptually represent completely different
operations, but are managed according to overlapping :term:`User` and :term:`Group` definitions.

.. _perm_public_access:

Public Access
-------------

In order to achieve publicly accessible :term:`Service` or :term:`Resource` functionality by any given individual,
the desired :term:`Permission` must be applied on *special* :term:`Group` defined with configuration setting
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_GROUP`. Since every existing :term:`User` automatically gets attributed
membership to that *special* :term:`Group` at creation time, all |applied_permissions|_ to it are inherited by
everyone, making the corresponding :term:`Resource` effectively :term:`Public`.

It is **VERY** important to apply :term:`Permission` on the *special* :term:`Group` defined by
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_GROUP` rather than then *special* :term:`User` defined by
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` in order to achieve :term:`Public`-like access by everyone.
This is because using the :term:`User` instead of the :term:`Group` would instead make the :term:`Resource`
accessible **ONLY** while not authenticated (i.e.: when :term:`Logged User` corresponds to
:py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`). Doing so would cause unnatural situations.
If the :term:`Permission` was applied for :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`, once a real
:term:`User` would authenticate itself, they would suddenly *lose* the :term:`Public` :term:`Permission` since
:term:`Logged User` would not be the *special* :term:`User` anymore (as if login to a different account).
That would lead to unexpected behavior where :term:`Resource` intended to be always :term:`Public` would
contextually change access criteria depending on active :term:`Logged User` session. More precisely, this would
cause confusing situation where an unauthenticated :term:`User` would be able to see publicly accessible elements,
but the same person wouldn't retain access to the same resources anymore as soon as he would authenticate itself
(login). That :term:`User` would have the impression that its access rights are lowered although they should
naturally expect increased privileges after authenticating itself.

Special :term:`User` :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` is available only for evaluation purpose of
:term:`Public`-only :term:`Permission` applied to :term:`Service` and :term:`Resource`, but is technically not required
to execute `Magpie` application. Effectively, when the active session corresponds to unauthenticated
:term:`Logged User`, it is still allowed to call :term:`User`-scoped API request paths, which will return details about
:term:`Public` accessible items.


.. _permission_modifiers:

Permission Definition and Modifiers
--------------------------------------

.. versionadded:: 3.0
    Previous versions of `Magpie` employed literal ``[permission_name]`` and ``[permission_name]-match`` strings to
    respectively represent recursive and exact match |perm_scope|_ over the tree hierarchy of :term:`Resource`.
    All ``-match`` suffixed :term:`Permission` names are now deprecated in favor of modifiers presented in this section.
    Furthermore, the :attr:`Access.DENY` concept is introduced via |perm_access|_ field, which did not exist at all in
    previous versions.

When applying a :term:`Permission` on a :term:`Service` or :term:`Resource` for a :term:`User` or :term:`Group`, there
are 3 components considered to interpret its definition:

1. |perm_name|_
2. |perm_access|_
3. |perm_scope|_

These concepts are implemented using :class:`magpie.permissions.PermissionSet`.

.. _perm_name:
.. |perm_name| replace:: ``name``

The |perm_name|_ represents the actual operation that is being attributed. For example, ``read`` and ``write`` would be
different |perm_name|_ that could be applied on a :term:`Resource` that represents a file. All allowed |perm_name|_
values are defined by :class:`magpie.permissions.Permission` enum, but the subset of |allowed_permissions|_ are
controlled per specific :term:`Service` and children :term:`Resource` implementations.

.. _perm_access:
.. |perm_access| replace:: ``access``

The |perm_access|_ component is defined by :class:`magpie.permissions.Access` enum. This specifies whether the
:term:`Permission` should be *allowed* or *denied*. More specifically, it provides flexibility to administrators to
correspondingly grant or remove the :term:`Permission` for previously denied or allowed :term:`User` or :term:`Group`
when resolving the :term:`Resource` tree hierarchy. This helps solving special use cases where different inheritance
conditions must be applied at different hierarchy levels. By default, if no |perm_access|_ indication is provided when
creating a new :term:`Permission`, :attr:`Access.ALLOW` is employed since `Magpie` resolves all |perm_access|_ to a
:term:`Resource` as :attr:`Access.DENY` unless explicitly granted. In other words, `Magpie` assumes that administrators
adding new :term:`Permission` entries intend to grant :term:`Service` or :term:`Resource` access for the targeted
:term:`User` or :term:`Group`. Any :term:`Permission` specifically created using :attr:`Access.DENY` should be involved
only to revert a previously resolved :attr:`Access.ALLOW`, as they are otherwise redundant to default
|effective_permissions|_ resolution.

.. _perm_scope:
.. |perm_scope| replace:: ``scope``

The |perm_scope|_ concept is defined by :class:`magpie.permissions.Scope` enum. This tells `Magpie` whether the
:term:`Applied Permissions <Applied Permission>` should impact only the immediate :term:`Resource`
(i.e.: when ``match``) or should instead be applied recursively for it and all its children. By applying a recursive
:term:`Permission` on a higher-level :term:`Resource`, this modifier avoids having to manually set the same
:term:`Permission` on every sub-:term:`Resource` when access as to be provided over a large hierarchy.
Also, when combined with the |perm_access|_ component, the |perm_scope|_ modifier can provide advanced control over
granted or denied access.

As a general rule of thumb, all :term:`Permission` are resolved such that more restrictive access applied *closer* to
the actual :term:`Resource` for the targeted :term:`User` will have priority, both in terms of inheritance by tree
hierarchy and by :term:`Group` memberships.

.. seealso::
    - |perm_example_modifiers|_
    - |perm_example_resolve|_

.. warning::
    Whenever possible, it is preferable and strongly advised to define new :term:`Permission` definitions using
    :attr:`Access.ALLOW` *as close as possible* to the target child :term:`Resource` for which to allow access,
    and leave the parent :term:`Resource` without any :term:`Permission` to let it be resolved by default to
    :attr:`Access.DENY` as well as any other :term:`Resource` under it except the explicitly allowed one.
    This is safer than the error prone alternative to :attr:`Access.ALLOW` everything at the root and revoke access
    at lower levels using :attr:`Access.DENY` to add "allowed exceptions" to the :term:`Resource` hierarchy. In case
    of incorrect request parsing, this second approach could potentially erroneously grant access to :term:`Resource`
    intended to be blocked. Using the first approach (only explicitly :attr:`Access.ALLOW` granted items) would still
    block by default all incorrectly parsed requests, ensuring children :term:`Resource` would still be protected.

.. _permission_representations:

Permissions Representation
--------------------------------------

.. |implicit| replace:: *implicit*
.. |explicit| replace:: *explicit*

.. versionadded:: 3.0
    Prior to this version, only plain *permission-names* where employed. These are represented by the |implicit| string
    representation in following versions of `Magpie`.

Basic Representation
~~~~~~~~~~~~~~~~~~~~~~~~

As presented in the previous section, every :term:`Permission` in `Magpie` is represented by three (3) elements, namely
the |perm_name|_, the |perm_access|_ and the |perm_scope|_. These are represented in API responses by both
|explicit| and |implicit| string representations, as well as one extensive JSON representation. The |implicit|
representation is mostly preserved for backward compatibility reasons, and represents the previous naming convention
which can *partially* be mapped to the |explicit| string representation, due to the addition of |perm_access|_ and
|perm_scope|_ modifiers.

Therefore, it can be noted that all API responses that contain details about permissions will return both the
``permission_names`` and ``permissions`` fields as follows.

.. code-block:: json

    {
        "permission_names": [
            "[permission-name]",
            "[name-access-scope]"
        ],
        "permissions": [
            {
                "name": "permission-name",
                "access": "allow|deny",
                "scope": "match|recursive",
                "type": "allowed|applied|direct|inherited|effective",
                "reason": "<optional>"
            }
        ]
    }

.. todo: (?) add "access|owned" to list of "type" if implemented alter on


The ``permission_names`` will return the combination of all applicable |implicit| and |explicit| string representations,
and could therefore contain duplicate entries in terms of representation. For example, the value ``"read"`` (|implicit|)
and the value ``"read-allow-recursive"`` (|explicit|) are both equivalent after interpretation to the JSON extended
format. The ``permissions`` list will ensure that no such duplicates will exist using JSON representation.

.. note::
    Single :term:`Permission` operations, such as creation, deletion or update of a permission entry will also provide
    all above variants, but without the plural ``s`` in the field names.

Extended Representation
~~~~~~~~~~~~~~~~~~~~~~~~

.. _perm_type:
.. |perm_type| replace:: ``type``

It can be noted that the previous JSON representation also provides a fourth |perm_type|_ parameter which serves as
indicative detail about the kind of :term:`Permission` being displayed. This field is provided in attempt to reduce
the ambiguity described in :ref:`permission_types`.

.. _perm_reason:
.. |perm_reason| replace:: ``reason``

.. versionadded:: 3.5
    Fifth field named |perm_reason|_ is introduced. It is also an informative field such as |perm_type|_ and does not
    impact the stored :term:`Permission`, but helps comprehend how :term:`ACL` gets resolved for a given :term:`User`.

Using field |perm_reason|_, it is possible to obtain an even more detailed explanation of the returned
:term:`Permission` set. This field can be represented with the following combinations:

.. list-table::
    :header-rows: 1

    * - Value/Format of |perm_reason|_
      - Description
    * - ``"administrator"``
      - Indicates that permission was granted because the :term:`User` has full administrative access over the
        corresponding :term:`Resource`. Typically, this means the :term:`User` is a member of
        :envvar:`MAGPIE_ADMIN_GROUP` and no further :term:`Permission` resolution needs to take place.
    * - ``"user:<id>:<name>"``
      - The resolved access to the :term:`Resource` is caused by the |direct_permissions|_ of the :term:`User`.
    * - ``"group:<id>:<name>"``
      - The resolved access to the :term:`Resource` is caused by an |inherited_permissions|_ the :term:`User`
        obtains through the specified :term:`Group` membership.
    * - ``"multiple"``
      - The resolved access to the :term:`Resource` is simultaneously caused by multiple |resolved_permissions|_
        of equal priority. This can be displayed when using ``resolve`` detailed below, and that not only a single
        :term:`Group` affects the resulting :term:`Permission`.
    * - ``"no-permission"``
      - The resolved access results into not a single :term:`Permission` found, defaulting to denied access.
        This occurs only during |effective_permissions|_ resolution where explicit :class:`Access` values must be
        returned for every possible :term:`Permission` |perm_name|_. Unspecified :term:`Permission` entries are simply
        omitted (as they don't exist) for every other type of request.


Field |perm_reason|_ is specifically useful when employed with ``inherited`` query parameter onto :term:`User`-scoped
request paths, as this option will simultaneously return all |inherited_permissions|_, both applied for the
:term:`User` itself and all its :term:`Group` memberships. Each of the listed :term:`Permission` would then individually
have its appropriate |perm_reason|_ field indicated, giving a broad overview of the applicable permissions for that
:term:`User` when processing |effective_permissions|_. Not using ``inherited`` would obviously only return
|direct_permissions|_, which will only contain ``"user:<id>:<name>"`` formatted |perm_reason|_ fields.

Furthermore, a *localized preview* of the |resolved_permissions|_ can be obtained by using query parameter
``resolve``. When this option is provided, `Magpie` will merge all |applied_permissions|_ of the :term:`User`
and its :term:`Group` memberships into a single entry (one per distinct :term:`Permission` |perm_name|_) over the
targeted :term:`Resource`. This offers a simplified view of the `Permissions Resolution`_ (although only locally),
to ease interpretation of |applied_permissions|_, notably when multiple :term:`Group` memberships with redundant,
complementary or even contradicting :term:`Permission` entries are defined on the same :term:`Resource`, which the
:term:`User` would inherit from.

.. warning::
    Field ``resolve`` does not return the *final* |effective_permissions|_ resolution (:attr:`Scope.RECURSIVE`
    is not considered in this case). It only indicates, *locally* for a given :term:`Resource`, the *most important*
    :term:`Applied Permission` of a :term:`User` amongst all of its existing |inherited_permissions|_.

.. seealso::
    - `Permissions Resolution`_
    - |perm_example_resolve|_


.. _perm_resolution:

Permissions Resolution
------------------------

This section details the step-by-step process employed to resolve |effective_permissions|_ to grant or refuse
:term:`User` access to a given :term:`Resource`. Some of the steps also apply to |inherited_permissions|_
resolution.

.. versionchanged:: 3.5
    Previous versions of `Magpie` considered every :term:`Group` with equal priority (step (2.2) in below list),
    not making any distinction between them although there are usually some implied priorities in practice. Later
    versions include step (2.3) to remediate this issue.

Below are the resolution steps which are applied for every distinct :term:`Permission` |perm_name|_ over a given
:term:`Resource` for which :term:`ACL` must be obtained:

.. cannot use the 'term' in replace, or it breaks the reference link creation
.. |steps_resolve_inherited| replace:: Inherited Permissions resolution
.. _steps_resolve_inherited:

.. container:: bordered-caption

    |inherited_permissions|_ resolution

.. container class generates '#.#' numbering with parent list reference automatically for proper alignment of text
.. container:: bordered-content parent-list-numbers
    :name: steps_resolve_inherited_block

    1. Any |direct_permissions|_ applied explicitly for the evaluated :term:`User` and :term:`Resource` combination
       are obtained. Any such :term:`Permission`, whether it is affected by :attr:`Access.ALLOW` or :attr:`Access.DENY`
       modifier dictates the :class:`Access` result over that :term:`Resource`.

    2. Following is the resolution of |inherited_permissions|_. In this case, there are three possibilities:

       1. There is only one :term:`Group` for which a :term:`Permission` is defined. The :term:`User` inherits that
          specification, whether it is :attr:`Access.ALLOW` or :attr:`Access.DENY`.

       2. Many :term:`Group` membership exist and share of same highest priority. In this case, if any :term:`Group`
          has :attr:`Access.DENY`, the resolved access is marked as denied. If every equally prioritized :term:`Group`
          indicate :attr:`Access.ALLOW`, then access is granted to the :term:`User`.

       3. Otherwise, the highest priority :term:`Group` dictates the :class:`Access` resolution. This can
          potentially *revert* a previous :term:`Group` decision.


The specific use case of step (2.3) is intended to give higher resolution precedence to any *generic* :term:`Group`
over the *special* :envvar:`MAGPIE_ANONYMOUS_GROUP` definition. This means that a *generic* :term:`Group` with a
:term:`Permission` affected by :attr:`Access.ALLOW` modifier can override *special* :envvar:`MAGPIE_ANONYMOUS_GROUP`
that would have :attr:`Access.DENY` for the same :term:`Resource`, although resolution is opposite in every other
situation. The reason for this exception is due to the nature of :envvar:`MAGPIE_ANONYMOUS_GROUP` membership that is
being automatically applied to every :term:`User` in order to also grant them `Public Access`_ to any :term:`Resource`
marked as accessible to anyone. Since that *special* :term:`Group` also represents *"unauthenticated users"*, it is
both counter intuitive and not practical to equally resolve conflicting |inherited_permissions|_ as it is
naturally expected that an authenticated :term:`User` with specific :term:`Group` memberships should receive higher
access privileges than its unauthenticated counterpart in case of contradictory :term:`Permission` across both
:term:`Group`. In other words, when a :term:`Resource` is blocked to the open public, it is expected that a
:term:`User` that would obtain access to that :term:`Resource` through another one of its :term:`Group` memberships
doesn't remain denied access due to its implicit :envvar:`MAGPIE_ANONYMOUS_GROUP` membership. Step (2.3) handles this
edge case specifically.

Every *generic* :term:`Group` (i.e.: others than :envvar:`MAGPIE_ANONYMOUS_GROUP` and :envvar:`MAGPIE_ADMIN_GROUP`)
share the same priority, and will therefore resolve conflicting :class:`Access` using the normal step conditions and
prioritizing :attr:`Access.DENY` (e.g.: step (2.2)).

When resolving only |inherited_permissions|_, the procedure stops here and provides the applicable result if any
was found, with the corresponding |perm_reason|_. An empty set of :term:`Permission` is returned if none could be found.

When instead resolving |effective_permissions|_, there are additional steps to the above
|steps_resolve_inherited|_ to consider special use-cases relative to administrative access as well as
scoped inheritance over the :term:`Resource` tree. The following resolution priority is accomplished:

.. cannot use the 'term' in replace, or it breaks the reference link creation
.. |steps_resolve_effective| replace:: Effective Permissions resolution
.. _steps_resolve_effective:

.. container:: bordered-caption

    |effective_permissions|_ resolution

.. container:: bordered-content
    :name: steps_resolve_effective_block

    1. | Resolve administrative access (i.e.: full access).
       | [only during |effective_permissions|_]
    2. | Resolution of |direct_permissions|_.
       | [same as step (1) of |steps_resolve_inherited|_]
    3. | Resolution of |inherited_permissions|_ from :term:`Group` memberships.
       | [same as step (2) of |steps_resolve_inherited|_]
    4. | Rewinding of the :term:`Resource` tree to consider scoped inheritance.
       | [only during |effective_permissions|_]

In this case, step (1) verifies if the :term:`User` is a member for :envvar:`MAGPIE_ADMIN_GROUP`.
In such case, :attr:`Access.ALLOW` is immediately returned for every possible |allowed_permissions|_ for the
targeted :term:`Resource` without further resolution involved.
The reason why this check is accomplished only during |effective_permissions|_ resolution is to avoid over
populating the database with :envvar:`MAGPIE_ADMIN_GROUP` :term:`Permission` for every possible :term:`Resource`.
It can be noted that effectively, ``"administrator"`` as :term:`Permission` ``reason`` will never be returned when
requesting any other type of :term:`Permission` than when specifying ``effective=true`` query, as there is no need
to explicitly define :envvar:`MAGPIE_ADMIN_GROUP` |applied_permissions|_.
Furthermore, doing this pre-check step ensures that :envvar:`MAGPIE_ADMIN_GROUP` members are always granted full access
regardless of any explicit :term:`Applied Permission` that could exist for that *special* :term:`Group`.

When the :term:`User` is not a member of :envvar:`MAGPIE_ADMIN_GROUP`, |effective_permissions|_ would then pursue to
steps (2) and (3) with the traditional |steps_resolve_inherited|_ listed earlier. The resolution process continues with
step (4) by rewinding the parent :term:`Resource` hierarchy until the first :term:`Permission` is found, or until the
root :term:`Service` is reached. Only on the first iteration (when the targeted :term:`Resource` is the same as the one
looked for potential |inherited_permissions|_) does :attr:`Scope.MATCH` take effect. Only :attr:`Scope.RECURSIVE` are
considered afterwards.

When the first :term:`Permission` is found, the procedure *remembers* the :class:`Access` of the
|resolved_permissions|_ for the current scope. If the found :term:`Permission` is linked directly to the
:term:`User`, the procedure stops with the active :class:`Access` as there  cannot be any higher priority
|inherited_permissions|_. Otherwise, the process continues rewinding further until an higher priority
:term:`Group` or any |direct_permissions|_ are found. An higher priority would override the previously matched
resolution scope and replaces the resolved :class:`Access`, while equal or lower priorities are ignored.
Doing so ensures that any |applied_permissions|_ *closer* to the targeted :term:`Resource` are respected, unless a
more important :term:`User` or :term:`Group` precedence dictates otherwise.

Once the hierarchy rewinding process completes, the resolved :class:`Access` is returned. If still no :term:`Permission`
could be found at that point, the result defaults to :attr:`Access.DENY`, and is indicated by ``"no-permission"``
for |perm_reason|_ field. Following pseudo-code presents the overall procedure.

.. cannot use the 'term' in replace, or it breaks the reference link creation
.. _algo_resolve_effective:
.. |algo_resolve_effective| replace:: Effective Permissions algorithm

.. code-block::
    :name: algo_resolve_effective_block
    :caption: |algo_resolve_effective|

    (1)     // Initialization
    (1.1)   target ← resource to resolve access or closest one (when non existing)
    (1.2)   match  ← enabled if target exists, otherwise disabled
    (1.3)   found  ← "no-permissions"
    (2)     // Verify administrative access
    (2.1)   if user is member of MAGPIE_ADMIN_GROUP
    (2.2)       found ← allow
    (2.3)       (done)
    (3)     // Resolve until completion
    (3.1)   while not (done)
    (3.2)       get applied permissions on target
    (3.3)       resolve(applied permissions, match)     // see Inherited Permissions resolution
    (3.4)       if resolved priority > found priority
    (3.5)           found ← resolved permission
    (4)         // Verify stopping rewind conditions
    (4.1)       if found == user direct permission      // highest permission found
    (4.2)           (done)
    (4.3)       if target == service                    // top of hierarchy reached
    (4.4)           (done)
    (5)         // Rewind parent resource to continue resolution
    (5.1)       target ← parent(target)
    (5.2)       match  ← disabled
    (done)  return found

.. seealso::
    - |perm_example_resolve|_

In some cases, :term:`Service` implementations will support simultaneous references to
multiple :term:`Resources <Resource>` with a single request.
One such example is when a request parameter allows a comma-separated list of values referring to
distinct :term:`Resource` items, for which :term:`Effective Resolution` must be computed for each element of the list.
When a :term:`Service` supports this type of references, the above |algo_resolve_effective|_ is applied
iteratively for every :term:`Resource` until all have been validated for :attr:`Access.ALLOW`, or until the first
:attr:`Access.DENY` is found. For this kind of |effective_permissions|_ to be granted access, **ALL** requested
:term:`Permission` on every :term:`Resources <Resource>` in the set must be :attr:`Access.ALLOW` indiscriminately.
Denied access to any element takes precedence over the whole set.

This procedure over multiple :term:`Resource` only applies during :term:`ACL` computation of an actual request to access
the remote :term:`Service` provider or one of its children :term:`Resource`. When managing |applied_permissions|_ on
:term:`Resource` definitions in `Magpie`, operations are always applied on elements individually.

.. versionadded:: 3.21
    Resolution over multiple simultaneous :term:`Resource` referred by a common request.


Examples
-------------------

.. _perm_example_search:
.. |perm_example_search| replace:: Permission Search example

Finding User Permissions
----------------------------

One of the trickiest (and often confusing) situation when we want to figure out which :term:`Service` a :term:`User`
has any :term:`Permission` on, is where to actually start looking? Effectively, if we have a vast amount of registered
:term:`Service`, each with a immense hierarchy of :term:`Resource`, doing an exhaustive search can be quite daunting,
not to mention costly in terms of request lookup and resources to go through.

For this purpose, there is one query parameter named ``cascade`` that can be employed with request
``GET /users/{user_name}/services``. In normal condition (without the parameter), this request responds with every
:term:`Service` where the user has |immediate_permissions|_ on (doesn't lookup the whole tree hierarchy). With the
added query parameter, it tells `Magpie` to recursively search the hierarchy of |applied_permissions|_ and return all
:term:`Service` instances that possess *any* :term:`Permission` given to at least one child :term:`Resource` at *any*
level. Furthermore, the ``cascade`` query can be combined with ``inherited`` query to search for all combinations of
|inherited_permissions|_ instead of (by default) only for the :term:`User`'s |direct_permissions|_.

This query can be extremely useful to quickly answer *"does the user have any permission at all on this service"*,
without needing to manually execute multiple successive lookup requests with all combinations of :term:`Resource`
identifiers in the hierarchy.

.. versionchanged:: 3.5
    As of this version, API responses also provide |perm_reason|_ field to help identify the source of every returned
    :term:`Permission`. Please refer to `Permissions Representation`_ for more details.


.. _perm_example_type:
.. |perm_example_type| replace:: Permission Types example

Distinguishing Applied, Inherited and Effective Permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section intends to provide more insight on the different :ref:`permission_types` using a simplified
demonstration of interaction between defined :term:`Service`, :term:`Resource`, :term:`Group`, :term:`User` and
:term:`Permission` elements.

Let's say we have some fictive :term:`Service` that allows the following *permission scheme*, and that it implements
the default hierarchical resolution of :term:`Resource` items.

.. code-block::

    service-type                [read | write]
        resource-type-1         [read | write]
            resource-type-2     [read | write]

.. note::
    To simplify this example, having permissions on ``resource-type-1`` also provides the same ones for child
    resources ``resource-type-2`` and so on. More explicitly, it is assumed that every :term:`Permission` is affected
    with (default) :class:`Scope.RECURSIVE` and :class:`Access.ALLOW` modifiers.
    See `Permission Definition and Modifiers`_ for further details on alternatives.

Given that scheme, let's say that existing elements are defined using the allowed types as follows:

.. code-block::

    service-1               (service-type)
    service-2               (service-type)
        resource-A          (resource-type-1)
    service-3               (service-type)
        resource-B1         (resource-type-1)
            resource-B2     (resource-type-2)

Let's says we also got a ``example-user`` that is member of ``example-group``, and that  |applied_permissions|_ on them
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
    /users/example-user/resources/service-2/permissions?inherited=true      => [write]  (1)
    /users/example-user/resources/resource-A/permissions?inherited=true     => [read]
    /users/example-user/resources/service-3/permissions?inherited=true      => [write]
    /users/example-user/resources/resource-B1/permissions?inherited=true    => [read]   (1)
    /users/example-user/resources/resource-B2/permissions?inherited=true    => []

As illustrated, requesting for |inherited_permissions|_ now also returns :term:`Group`-related :term:`Permission`
:sup:`(1)` where they where not returned before with only :term:`User`-related :term:`Permission`.

On the other hand, using ``effective`` would result in the following:

.. code-block::

    /users/example-user/resources/service-1/permissions?effective=true      => [write]
    /users/example-user/resources/service-2/permissions?effective=true      => [write]          (2)
    /users/example-user/resources/resource-A/permissions?effective=true     => [read, write]    (3)
    /users/example-user/resources/service-3/permissions?effective=true      => []
    /users/example-user/resources/resource-B1/permissions?effective=true    => [read]           (2)
    /users/example-user/resources/resource-B2/permissions?effective=true    => [read, write]    (4)

In this case, all :term:`Resource` entries that had :term:`Permission` directly set on them :sup:`(2)`, whether through
:term:`User` or :term:`Group` combination, all return the exact same set of :term:`Permission`. This is because
|effective_permissions|_ always imply |inherited_permissions|_ (i.e.: using both query simultaneously is redundant).
The reason why we obtain these sets for cases :sup:`(2)` is also because there is no other :term:`Permission` applied
to any of their parent :term:`Service` or :term:`Resource`. Contrarily, ``resource-A`` :sup:`(3)` now additionally
receives :term:`Permission` ``read`` indirectly from its parent ``service-2`` (note: ``write`` is redundant here).
Similarly, ``resource-B2`` :sup:`(4)` which did not even have any immediate :term:`Permission` applied to it,
now receives both ``read`` and ``write`` access, respectively from its parents ``resource-B1`` and ``service-3``. This
demonstrates why, although |effective_permissions|_ imply |inherited_permissions|_, they do not necessarily resolve to
the same result according to the effective :term:`Resource` hierarchy and its parent-children resolution implementation.

Using ``effective`` query tells `Magpie` to rewind the :term:`Resource` tree from the requested :term:`Resource` up to
the top-most :term:`Service` in order to accumulate all |inherited_permissions|_ observed along the way for every
encountered element. All :term:`Permission` that is applied *higher* to the requested :term:`Resource` are considered
as if applied directly on it. Query parameter ``inherited`` limits itself only to specifically requested
:term:`Resource`, without hierarchy resolution, but still considering :term:`Group` memberships. For this reason,
``inherited`` *could* look the same to ``effective`` results if the :term:`Service` hierarchy is "flat", or if all
:term:`Permission` can be found directly on the target :term:`Resource`, but it is not guaranteed. This is further
important if the :term:`Service`'s type implementation provides custom methodology for parsing the hierarchy resolution
(see :ref:`services` for more details).

In summary, ``effective`` tells us *"which permissions does the user have access to for this resource"*, while
``inherited`` answers *"which permissions does the user have on this resource alone"*, and without any query, we
obtain *"what are the permissions that this user explicitly has on this resource"*.

.. _perm_example_modifiers:
.. |perm_example_modifiers| replace:: Permission Modifiers example

Effect of Permission Modifiers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. seealso::
    Section :ref:`permission_modifiers` provides details about concepts relative to this example.

Below are examples of :term:`Permission` definitions that can help better understand the different concepts.
The definitions employ the ``[name]-[access]-[scope]`` convention to illustrate the applied :term:`Permission`.

.. code-block::

    ServiceA                (UserA, read-allow-recursive)
        Resource1           (UserA, write-allow-match)
            Resource2       (UserA, read-deny-match)
                Resource3
    ServiceB
        Resource4           (UserA, write-allow-match)
            Resource5
                Resource6   (UserA, read-allow-match) (UserA, write-allow-match)


In this example, ``UserA`` is granted ``read`` access to ``ServiceA``, ``Resource1`` and ``Resource3`` because of the
``recursive`` scope applied on ``ServiceA``. Access ``deny`` is explicitly applied on ``Resource2`` with ``match``
scope, meaning that only that resource is specifically blocked by overriding (or reverting) the granted higher level
``read-allow-recursive``. If ``recursive`` was instead used on ``Resource2``, ``Resource3`` would also have been
blocked. The ``write`` permission is also granted to ``UserA`` for ``Resource1``, but no other item in the ``ServiceA``
branch can be *written* by ``UserA`` since ``match`` scope was used and ``deny`` is the default resolution method.
Similarly, only ``Resource4`` and ``Resource6`` will ``allow`` the ``write`` permission under branch ``ServiceB``.
Note that different permission ``names`` can be applied simultaneously, such as for the case of ``Resource6``.
This will effectively grant ``UserA`` both of these permissions on ``Resource6``. Other |perm_access|_ and |perm_scope|_
concepts can only have one occurrence over same |perm_name|_ combination on a given hierarchy item, as they would define
conflicting interpretation of |effective_permissions|_.

The above example presents only the resolution of :term:`User` permissions. When actually resolving
|effective_permissions|_, all |inherited_permissions|_ from its :term:`Group` memberships are also considered
in the same fashion. The :term:`Group` permissions complement definitions specifically applied to a :term:`User`.
In case of conflicting situations, such as when ``allow`` is applied via |direct_permissions|_
and ``deny`` is defined via |inherited_permissions|_ for same :term:`Resource`, |direct_permissions|_ have
priority over any :term:`Group` :term:`Permission`. Also, ``deny`` access is prioritized over ``allow`` to preserve
the default interpretation of protected access control defined by `Magpie`. When ``match`` and ``recursive`` scopes
cause ambiguous resolution, the ``match`` :term:`Permission` is prioritized over inherited access via parent
|perm_scope|_.


.. _perm_example_resolve:
.. |perm_example_resolve| replace:: Permission Resolution example

Resolution of Permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example will demonstrate the simultaneous resolution of all following concepts to obtain
|effective_permissions|_ of a :term:`User` over a given targeted :term:`Resource`:

- Combining |direct_permissions|_ and |inherited_permissions|_ (see :ref:`permission_types`)
- Having multiple |inherited_permissions|_ with different or equal :term:`Group` priorities
- Getting access from local and hierarchical :class:`Scope` modifier (see `Basic Representation`_)
- Reverting access using :class:`Access` modifier at different levels (see `Basic Representation`_)

It is recommended to have a general understanding of all the concepts by going though corresponding sections that
describe them individually and in more details.

We start by defining the following :term:`Service` and :term:`Resource` hierarchy. We employ the :ref:`ServiceAPI`
implementation that only allows one type of :term:`Resource` (i.e.: ``route``), and that easily converts path elements
into the given hierarchy. In this case, every :term:`Resource` can be applied with either :attr:`Permission.READ`
(``r``) or :attr:`Permission.WRITE` (``w``).
For a compact display, we indicate :attr:`Access.ALLOW` (``A``), :attr:`Access.DENY` (``D``),
:attr:`Scope.MATCH` (``M``) and :attr:`Scope.RECURSIVE` (``R``) using the ``[name]-[access]-[scope]``
representation for |applied_permissions|_.

.. code-block::

    Resource Hierarchy                | TestUser      | TestGroup1    | TestGroup2    | Anonymous
                                      | [user]        | [group]       | [group]       | [special-group]
    ==================================+=======+=======+=======+=======+=======+=======+=======+========
    service-A [api]                   | r-A-M |       |       |       |       |       |       | w-A-R
        resource-1 [route]            |       |       |       |       |       |       | r-D-R |
            [unspecified-1]           |   -   |   -   |   -   |   -   |   -   |   -   |   -   |   -
            resource-2 [route]        |       |       |       | w-A-R | r-A-R |       |       | w-D-R
                [unspecified-2]       |   -   |   -   |   -   |   -   |   -   |   -   |   -   |   -
                resource-3 [route]    |       | w-D-M |       |       |       |       |       |
                    [unspecified-3]   |   -   |   -   |   -   |   -   |   -   |   -   |   -   |   -
        resource-4 [route]            |       |       | r-D-R |       | r-A-R |       |       | w-D-R
            resource-5 [route]        |       |       |       |       | r-A-R |       |       |

.. note::
    Items with ``[unspecified-#]`` identifiers are employed to indicate path element that would land onto
    non existing :term:`Resource` (e.g.: ``/service-A/resource-1/Unknown`` mapped to ``[unspecified-1]``), but that
    will still obtain |effective_permissions|_ affected by any applied :attr:`Scope.RECURSIVE` modifier on parent
    :term:`Resource` locations (i.e.: resources that *would* be its parent if it did exist). Because ``[unspecified-#]``
    items do not exist, there cannot be any corresponding |applied_permissions|_ on them, as indicated by ``-`` mark.

Presented below is the resolved |effective_permissions|_ matrix of ``TestUser`` considering above definitions.

.. |check| unicode:: U+2713
.. |cross| unicode:: U+2715

.. list-table::
    :header-rows: 1
    :widths: 5,5,5,85

    * - Target
      - Permission
      - Access
      - Detail
    * - ``service-A``
      - ``read``
      - |check|
      - Access is granted because |direct_permissions|_ on ``service-A`` takes precedence over everything.
        Only ``TestUser`` has this permission, other users in ``TestGroup1``, ``TestGroup2`` and public access are
        all denied, unless other user also has some explicit permission or other group membership that grants access.
    * - ``service-A``
      - ``write``
      - |check|
      - Access is granted because of |inherited_permissions|_ from :envvar:`MAGPIE_ANONYMOUS_GROUP`.
        In this case, anyone will obtain public access, not only ``TestUser``.
    * - ``resource-1``
      - ``read``
      - |cross|
      - :term:`Applied Permission` with recursively denied access for :envvar:`MAGPIE_ANONYMOUS_GROUP` makes
        ``resource-1`` *publicly* inaccessible for reading. Since the other ``read`` permission on parent ``service-A``
        is affected to ``match`` scope, it does not propagate its scope onto ``resource-1`` for resolution.
    * - ``resource-1``
      - ``write``
      - |check|
      - No |applied_permissions|_ is defined directly on ``resource-1``, but the inherited scope from
        ``service-1`` makes it *publicly* writable with :envvar:`MAGPIE_ANONYMOUS_GROUP` permission.
    * - ``resource-2``
      - ``read``
      - |check|
      - ``TestUser`` obtains access from its membership from ``TestGroup2`` that allows access.
        It overrides :envvar:`MAGPIE_ANONYMOUS_GROUP` defined access on ``resource-1`` by group priority.
    * - ``resource-2``
      - ``write``
      - |check|
      - Similarly to previous case, ``TestGroup1`` grants access over :envvar:`MAGPIE_ANONYMOUS_GROUP` denied access.
    * - ``resource-3``
      - ``read``
      - |check|
      - ``TestUser`` obtains access again from its membership to ``TestGroup2`` that allows recursive ``read`` access.
        Contrary to ``resource-2`` that only resolved group priority, scope inheritance is also involved in this case.
    * - ``resource-3``
      - ``write``
      - |cross|
      - Explicit denied access by |direct_permissions|_ onto ``resource-3`` overrides anything specified at higher
        level in the hierarchy. Although granted access is defined by ``TestGroup1`` at higher level, user permission
        takes precedence over |inherited_permissions|_.
    * - ``[unspecified-1]``
      - ``read``
      - |cross|
      - Because the resource does not exist, this path element can only inherit from recursive parent scope.
        The only applicable permission is the denied ``read`` access on ``resource-1`` for
        :envvar:`MAGPIE_ANONYMOUS_GROUP`. The resource is therefore blocked.
        Not having any permission would result by default to the same refused access.
    * - ``[unspecified-1]``
      - ``write``
      - |check|
      - Special :envvar:`MAGPIE_ANONYMOUS_GROUP` provides recursive access, and therefore publicly allows ``write``
        access to this path segment. Any combination of ``/service-A/resource-1/<ANYTHING>`` will allow writing
        operations.
    * - ``[unspecified-2]``
      - ``read``
      - |check|
      - All values matching this position are allowed because of ``TestGroup2`` recursive access, as previous cases.
    * - ``[unspecified-2]``
      - ``write``
      - |check|
      - All values are again allowed **except** ``resource-3``. Because that entry exists and has explicit deny for
        ``TestUser``, it will be blocked. Another unspecified value at same position will not be blocked.
    * - ``[unspecified-3]``
      - ``read``
      - |check|
      - As all other resources nested under ``resource-2``, ``TestGroup2`` memberships grants access to this location
        for reading. The permission will also keep propagating indefinitely, allowing even deeper request path such
        as ``/service-A/resource-1/resource-2/a/b/c/d``.
    * - ``[unspecified-3]``
      - ``write``
      - |check|
      - Although access was explicitly denied to ``TestUser`` on ``resource-3``, scope ``match`` does not propagate
        to lower resources. Anything at this level inherits from allowed access of ``TestGroup1`` membership.
        Non ``TestGroup1`` members are still forbidden access due to recursive denial on
        :envvar:`MAGPIE_ANONYMOUS_GROUP`.
    * - ``resource-4``
      - ``read``
      - |cross|
      - Both groups ``TestGroup1`` and ``TestGroup2`` contradict (one deny and the other allow). Because they have
        equal group priority, the resolved permission favors denied access.
    * - ``resource-4``
      - ``write``
      - |check|
      - Allowed from :envvar:`MAGPIE_ANONYMOUS_GROUP` recursive access.
    * - ``resource-5``
      - ``read``
      - |check|
      - Although both groups ``TestGroup1`` and ``TestGroup2`` specify opposite permissions on parent ``resource-4``,
        the definition on ``resource-5`` from ``TestGroup2`` is *closer* than the ``TestGroup1`` denied access. The
        allowed access takes precedence in this case because of scoped access that is not overridden by equal priority
        groups at higher hierarchy levels.
    * - ``resource-5``
      - ``write``
      - |check|
      - Allowed from :envvar:`MAGPIE_ANONYMOUS_GROUP` recursive access.

