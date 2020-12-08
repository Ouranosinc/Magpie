.. _permissions:
.. include:: references.rst

.. default location to quickly reference items without the explicit and long prefix
.. using the full name when introducing the element (to make the location obvious), the reuse shorthand variant
.. py:currentmodule:: magpie.permissions

Permissions
===========

.. _permission_types:

Types of Permissions
-----------------------

Across the documentation and the code, term :term:`Permission` is often employed interchangeably to represent different
and more subtle contextual functionalities. This is mostly an abuse of language, but is preserved regardless in order
to maintain backward compatibility of features and API response content with older systems that could employ `Magpie`.
Therefore, care must be taken to consider under which context this term is observed to ensure correct interpretation
of observed results.

.. versionchanged:: 3.0
    Following the introduced :ref:`Permission Representations` as JSON objects with this version, a new
    :class:`magpie.permissions.PermissionType` enum was added to make following types more explicit. Responses from
    the API will include a ``type`` field that indicates precisely the type of :term:`Permission` returned, for each
    specific item presented below.

.. seealso::
    - `Permissions Representation`_
    - |perm_example_type|_

More specifically, following distinctions can be observed between different kind of :term:`Permission` used by `Magpie`:

.. _`allowed permissions`:

- **Allowed Permissions**:
    Represents the set of valid :term:`Permission` values that *could* be applied to a given :term:`Service` or
    :term:`Resource`, depending on their type's implementation. Every allowed :term:`Permission` is one entry from
    :py:data:`magpie.permissions.Permission`, and their set define the *schema* that will pass validation if applied
    to corresponding items of :py:mod:`magpie.services`, but they are not necessarily an active nor existing entry
    in the database (i.e.: `Applied Permissions`_). In general, these values are obtained from requests scoped under
    paths ``/service`` and ``/resources``.

.. _`applied permissions`:

- **Applied Permissions**:
    Represents an active "rule" which defines a combination of ``(User|Group, Service|Resource, Permission)``.
    These entries are validated during requests against the appropriate `Allowed Permissions`_ of the targeted item
    (:term:`Service` or :term:`Resource`) to create the "rule" under (for) the targeted :term:`User` or :term:`Group`.
    When executing requests under scopes ``/users`` and ``/groups``, responses without query parameter modifiers
    are by default `Applied Permissions`_. These are also scoped under a *single context* at a given time
    (:term:`User` or :term:`Group`), depending on the request path being executed. They determine
    which access rights will be granted or denied for the respective :term:`User` or :term:`Group`.

.. _`direct permissions`:

- **Direct Permissions**:
    Explicitly represents :term:`Applied Permissions` "rules" in the case of :term:`User` context, which is, when
    :term:`Group` membership are **NOT** considered (i.e.: :term:`Inherited Permissions`). Since calling ``/users``
    scoped requests can lead to all different :term:`Permission` variations presented here with different contextual
    information, this term is employed to specifically indicate the situations of the default behaviour of the routes
    without query parameters.

.. _`immediate permissions`:

- **Immediate Permissions**:
    Represents a "rule" combination that was explicitly applied to a :term:`Service`. Rules applied to children
    :term:`Resource` are **NOT** considered :term:`Immediate Permissions` (they are simply `Applied Permissions`_
    without any special connotation). Note that `Immediate Permissions`_ are still `Applied Permissions`_.
    They are a special subset of `Applied Permissions`_ matching how :term:`Service` are a specialized implementation
    of :term:`Resource` (see: :class:`magpie.models.Service`). This kind of :term:`Permissions` is notably referred
    to by requests for `Finding User Permissions`_ as they provide useful and unique properties.

.. _`inherited permissions`:

- **Inherited Permissions**:
    Represents the combined set of `Applied Permissions`_ from the :term:`User` context and every one of its
    :term:`Group` membership contexts. When requesting a :term:`Group`'s permissions, only "rules" explicitly set on
    the given group are returned. The same concept applies when *only* requesting :term:`User` permissions. Providing
    applicable :term:`User`-scoped requests with ``inherited=true`` query parameter will return the complete set of
    `Applied Permissions`_ for that :term:`User` and all his :term:`Group` membership simultaneously.
    See |perm_example_type|_ for comparison of results with different query parameters.

    .. versionchanged:: 2.0
        Prior to this version, ``inherit`` (without ``ed``) was employed as query parameter name. This often lead to
        confusion between expected and returned results due to mistakenly employed adjective. Because they are referred
        to as :term:`Inherited Permissions` in the documentation and naturally from a linguistic standpoint, query
        ``inherited`` (with ``ed``) is now the *official* parameter. The older variant remains supported and equivalent.

.. _`effective permissions`:

- **Effective Permissions**:
    Represents all `Inherited Permissions`_ of the :term:`User` and all its :term:`Group` membership, as well as the
    extensive resolution of the :term:`Service` and every children :term:`Resource` in its hierarchy for the requested
    :term:`Resource` scope. Effective permissions automatically imply ``inherited=True``, and can be obtained from
    :term:`User`-scoped requests with ``effective=true`` query parameter wherever supported.
    See |perm_example_type|_ for complete comparison.

.. _`access permissions`:

- **Access Permissions**:
    Represents the required level of :term:`Permission` needed to access `Magpie` API routes to request details. These
    can be referred to as "roles", but are inferred by :term:`Group` memberships of the :term:`Logged User` attempting
    to complete the request. It is the only kind of :term:`Permission` which the values are not retrieved from the
    enum :class:`magpie.permissions.Permission`, but rather from a combination of special :term:`Group` and
    :ref:`Configuration` constants. See `Route Access`_ for more details.

.. following are potential but not implemented / unused:
    ownership permissions:
        user/group that owns the service/resource
        defined with the id saved directly under that Resource (see Resource.owner_[user|group]_id)
    role permission:
        (user|group, permission) relationship, within separate tables in database
        maybe could be combined used with group permissions and 'access permissions' do, but there
        is still a need to check view access dynamic group with them, might require some GroupFactory?


Route Access
-------------

Most of the HTTP routes require by default administrative privileges (i.e.: ``MAGPIE_ADMIN_PERMISSION`` or equivalent
inferred from ``MAGPIE_ADMIN_GROUP`` membership for the :term:`Logged User`). Exceptions to this are notably requests
with :term:`User`-scoped routes under ``/users/{user_name}`` which allow retrieval of :term:`Public` :term:`Resource`
details (e.g.: obtaining information about what ``MAGPIE_ANONYMOUS_GROUP`` members have access to), and informative
API routes that are granted :ref:`Public Access` to anyone such as the `Magpie REST API`_ documentation served under
a running `Magpie` instance or the instance's version route.

.. versionchanged:: 2.0

    Some routes under ``/users/{user_name}`` are also granted more *contextual access* than the default admin-only
    access requirement to allow self-referencing user operations. Using a combination of view configurations with
    :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` and
    :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION`, the permitted functionalities are controlled according to
    the actual procedure being executed. In other words, if the :term:`Request User` corresponds to the path variable
    :term:`Context User`, access *could* also granted to allow that individual to obtain or update its own details.
    In this situation, allowed routes are controlled on a per-request basis with for the respective contextual
    operations accomplished by each request. For example, :term:`Logged User` could be granted access to update its
    account details, but won't be able to grant itself more permissions on a given :term:`Service` or :term:`Resource`.

Typically, request `Access Permissions`_ fall into one of the following category for all API endpoints. Higher
permissions in the table typically imply higher access conditions.

.. list-table::
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

1. :term:`Logged User` has administrative-level `Access Permissions`_ (always granted access).
2. :term:`Context User` corresponds exactly to same :term:`Request User` identified from the path variable.
3. :term:`Context User` in path variable is the special keyword :py:data:`magpie.constants.MAGPIE_LOGGED_USER`.
4. :term:`Context User` in path variable is special user :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`.

For the first matched of the above steps, the condition is compared to the specific request requirement.
Access is granted or denied according to met or insufficient condition result.

Every time a :term:`User`-scoped request is executed, the targeted :term:`Context User` is resolved accordingly to
either the explicit ``{user_name}}`` value provided, or the auto-resolved :py:data:`magpie.constants.MAGPIE_LOGGED_USER`
value that implicitly retrieves the :term:`Request User` as the :term:`Context User`.

.. note::
    Whenever one of the :term:`User`-scoped requests refers to specials keywords such as
    :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` or :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP`, any operation
    that has the intention to modify the corresponding :term:`User` or :term:`Group` are forbidden. There is therefore
    some additional request-specific logic (depending on its purpose and resulting actions) for special-cases that is
    not explicitly detailed in above steps. Some of these special behaviors can be observed across the various `tests`_.


Finally, it is worth further detailing the small distinction between
:py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` and :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION`,
provided that they act almost the same way. More precisely, they both work in the exact situation where
:term:`Request User` is equal to :term:`Context User`, but each for different sets of applicable values for those
:term:`User` references.

When a route is attributed :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION`, it means that the :term:`Request User`
must absolutely be authenticated (i.e.: not ``None``), while :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION` does
not enforce this criteria. The *contextual* permission is an extended set of the *logged* one with two exceptions, which
are when the :term:`Request User` is unauthenticated and/or when the referenced :term:`Context User` is resolved to the
unauthenticated :term:`User` defined by :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`.

An example where such distinction is important goes as follows. A request that requires to update :term:`User`
details typically *minimally* requires a :term:`Logged User` because it does not make sense to attempt modification
of an undefined :term:`User`. If the :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION` requirement was applied, it
would imply that unauthenticated :term:`Context User` *could* update itself, which is obviously wrong. On the other
hand, it makes sense to allow the :term:`Request User` to update its own details. In this case, the applicable view
configuration is :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` so that it immediately forbids the operation if
the :term:`Request User` did not accomplish prior :term:`Authentication`. As counter example, requesting details about
resources that are :term:`Public` (more details in :ref:`Public Access` for this), makes sense even when we did not
complete prior :term:`Authentication`, as they are accessible to everyone. The view configuration in this case should
employ :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION` so that :term:`Context User` referring to unauthenticated
:term:`User` will be permitted. They cannot be set to :py:data:`pyramid.security.Authenticated`, as this would enforce
the need to signin in first, while :py:data:`pyramid.security.NO_PERMISSION_REQUIRED` would fully open *all* requests
targeting for example an administrator as :term:`Context User`. It is important to distinguish in this situation between
:ref:`Access Permissions` of the view configuration and listed :ref:`Applied Permissions` on resources.

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
contextually change access criteria depending on active :term:`Logged User` session. More precisely, this would cause
confusing situation where an unauthenticated :term:`User` would be able to see publicly accessible elements, but
wouldn't see them anymore as soon as he would authenticate itself (login). That :term:`User` would have the impression
that its access rights are lowered although they should be increased by authenticating itself.

Special user :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER` is available only for evaluation purpose of
:term:`Public`-only :term:`Permission` applied to :term:`Service` and :term:`Resource`, but is technically not required
to execute `Magpie` application. Effectively, when the active session corresponds to unauthenticated
:term:`Logged User`, it is still allowed to call :term:`User`-scoped API request paths, which will return details about
:term:`Public` accessible items.


Finding User Permissions
----------------------------

One of the trickiest (and often confusing) situation when we want to figure out which :term:`Service` a :term:`User` has
any :term:`Permission` on, is where to actually start looking? Effectively, if we have a vast amount of registered
:term:`Service` each with a immense hierarchy of :term:`Resource`, doing an exhaustive search can be quite daunting,
not to mention costly in terms of request lookup and resources.

For this purpose, there is one query parameter named ``cascade`` that can be employed with request
``GET /users/{user_name}/services``. In normal condition (without the parameter), this request responds with every
:term:`Service` where the user has :term:`Immediate Permissions` on (doesn't lookup the whole tree hierarchy). With the
added query parameter, it tells `Magpie` to recursively search the hierarchy of `Applied Permissions`_ and return all
:term:`Service` instances that possess *any* :term:`Permission` given to at least one child :term:`Resource` at *any*
level. Furthermore, the ``cascade`` query can be combined with ``inherited`` query to search for all combinations of
:term:`Inherited Permissions` instead of (by default) only for the :term:`User`'s :term:`Direct Permissions`.

This query can be extremely useful to quickly answer *"does the user have any permission at all on this service"*,
without needing to manually execute multiple successive lookup requests with all combinations of :term:`Resource`
identifiers in the hierarchy.

.. versionchanged:: 3.4
    As of this version, API responses also provide ``reason`` field to help identify the source of every returned
    :term:`Permission`. Please refer to `Permissions Representation`_ for more details.

.. _permission_modifiers:

Permission Definition and Modifiers
--------------------------------------

.. versionadded:: 3.0
    Previous versions of `Magpie` employed literal ``[permission_name]`` and ``[permission_name]-match`` to
    respectively represent recursive and exact match ``scope`` over the tree hierarchy of :term:`Resource`.
    All ``-match`` suffixed :term:`Permission` names are now deprecated in favor of modifiers presented in this section.
    Furthermore, the :attr:`Access.DENY` concept is introduced via ``access`` field, which did not exist at all in
    previous versions.

When applying a :term:`Permission` on a :term:`Service` or :term:`Resource` for a :term:`User` or :term:`Group`, there
are 3 components considered to interpret its definition:

1. ``name``
2. ``access``
3. ``scope``

These concepts are implemented using :class:`magpie.permissions.PermissionSet`.

The ``name`` represents the actual operation that is being attributed. For example, ``read`` and ``write`` would be
different ``name`` that could be applied on a :term:`Resource` that represents a file. All allowed ``name`` values
are defined by :class:`magpie.permissions.Permission` enum, but the subset of :term:`Allowed Permissions` are controlled
per specific :term:`Service` and children :term:`Resource` implementations.

The ``access`` component is defined by :class:`magpie.permissions.Access` enum. This specifies whether the
:term:`Permission` should be *allowed* or *denied*. More specifically, it provides flexibility to administrators to
correspondingly grant or remove the :term:`Permission` for previously denied or allowed :term:`User` or :term:`Group`
when resolving the :term:`Resource` tree hierarchy. This helps solving special use cases where different inheritance
conditions must be applied at different hierarchy levels. By default, if no ``access`` indication is provided when
creating a new :term:`Permission`, :attr:`Access.ALLOW` is employed since `Magpie` resolves all ``access`` to a
:term:`Resource` as :attr:`Access.DENY` unless explicitly granted. In other words, `Magpie` assumes that administrators
adding new :term:`Permission` entries indent to grant :term:`Service` or :term:`Resource` access for the targeted
:term:`User` or :term:`Group`. Any :term:`Permission` specifically created using :attr:`Access.DENY` should be involved
only to revert a previously resolved :attr:`Access.ALLOW`, as they are otherwise redundant to default
:term:`Effective Permissions` resolution.

The ``scope`` concept is defined by :class:`magpie.permissions.Scope` enum. This tells `Magpie` whether the
:term:`Applied Permission` should impact only the immediate :term:`Resource` (i.e.: when ``match``) or should instead
be applied recursively for it and all its children. By applying a recursive :term:`Permission` on a higher-level
:term:`Resource`, this modifier avoids having to manually set the same :term:`Permission` on every sub-:term:`Resource`
when access as to be provided over a large hierarchy. Also, when combined with the ``access`` component, the ``scope``
modifier can provide advanced control over granted or denied access.

As a general rule of thumb, all :term:`Permission` are resolved such that more restrictive access applied *closer* to
the actual :term:`Resource` for the targeted :term:`User` will have priority, both in terms of inheritance by tree
hierarchy and by :term:`Group` memberships.

.. seealso::
    - |perm_example_modifiers|_
    - |perm_example_resolution|_

.. _permission_representations:

Permissions Representation
--------------------------------------

Basic Representation
~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: 3.0
    Prior to this version, only plain *permission-names* where employed. These are represented by the *implicit* string
    representation in following versions of `Magpie`.

As presented in the previous section, every :term:`Permission` in `Magpie` is represented by three (3) elements, namely
the ``name``, the ``access`` and the ``scope``. These are represented in API responses by both *explicit* and *implicit*
string representations, as well as one extensive JSON representation. The *implicit* representation is mostly preserved
for backward compatibility reasons, and represents the previous naming convention which can **partially* be mapped to
the *explicit* string representation, due to the addition of ``access`` and ``scope`` modifiers.

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
                "type": "access|allowed|applied|direct|inherited|effective|owned",
                "reason": "<optional>"
            }
        ]
    }


.. note::
    Single :term:`Permission` operations, such as creation, deletion or update of a permission entry will also provide
    all above variants, but without the plural ``s`` in the field name.

Extended Representation
~~~~~~~~~~~~~~~~~~~~~~~~

It can be noted that the previous JSON representation also provides a fourth ``type`` parameter which serves as
indicative detail about the kind of :term:`Permission` being displayed, in attempt to reduce the ambiguity described in
:ref:`permission_types`.

.. versionadded:: 3.4
    Fifth field named ``reason`` is introduced. It is also an informative field such as ``type`` and does not impact
    the stored :term:`Permission`, but helps comprehend how :term:`ACL` gets resolved for a given :term:`User`.

Using field ``reason``, it is possible to obtain an even more detailed explanation of the returned :term:`Permission`
set. This field can be represented with the following combinations:

.. list-table::
    :header-rows: 1

    * - Value/Format of ``reason``
      - Description
    * - ``"administrator"``
      - Indicates that permission was granted because the :term:`User` has full administrative access over the
        corresponding :term:`Resource`. Typically, this means the :term:`User` is a member of ``MAGPIE_ADMIN_GROUP``
        and no further :term:`Permission` resolution needs to take place.
    * - ``"user:<id>:<name>"``
      - The resolved access to the :term:`Resource` is caused by the :term:`Direct Permissions` of the :term:`User`.
    * - ``"group:<id>:<name>"``
      - The resolved access to the :term:`Resource` is caused by an :term:`Inherited Permissions` the :term:`User`
        obtains through the specified :term:`Group` membership.
    * - ``"multiple"``
      - The resolved access to the :term:`Resource` is simultaneously caused by multiple :term:`Inherited Permissions`
        of equal priority. This can be displayed when using ``resolve`` detailed below, and that not only a single
        :term:`Group` affects the resulting :term:`Permission`.
    * - ``"no-permission"``
      - The resolved access results into not a single :term:`Permission` found, defaulting to denied access.
        This occurs only during :term:`Effective Permissions` resolution where explicit :class:`Access` values must be
        returned for every possible :term:`Permission` ``name``. Unspecified :term:`Permission` entries are simply
        omitted (as they don't exist) for every other type of request.


Field ``reason`` is specifically useful when employed with ``inherited`` query parameter onto :term:`User`-scoped
request paths, as this option will simultaneously return all :term:`Inherited Permissions`, both applied for the
:term:`User` itself and all its :term:`Group` memberships. Each of the listed :term:`Permission` would then individually
have its appropriate ``reason`` field indicated, giving a broad overview of the applicable permissions for that
:term:`User` when processing :term:`Effective Permissions`. Not using ``inherited`` would obviously only return
:term:`Direct Permissions`, which will only return ``"user:<id>:<name>"`` formatted ``reason`` fields.

Furthermore, a *localized preview* of the resolved :term:`Permission` can be obtained by using query parameter
``resolve``. When this option is provided, `Magpie` will merge all :term:`Applied Permissions` of the :term:`User`
and its :term:`Groups` into a single entry (one per distinct :term:`Permission` ``name``) over the targeted
:term:`Resource`. This offers a simplified view of the `Permissions Resolution`_ (although only locally), to ease
interpretation of :term:`Applied Permissions`, notably when multiple :term:`Group` memberships with redundant,
complementary or even contradicting :term:`Permission` entries on the :term:`Resource` are defined, which the
:term:`User` would inherit from.

.. seealso::
    - `Permissions Resolution`_
    - |perm_example_resolution|_

.. warning::
    Field ``resolve`` does not return the *final* :term:`Effective Permissions` resolution (:attr:`Scope.RECURSIVE` is
    not considered in this case). It only indicates, *locally* for a given :term:`Resource`, the *most important*
    :term:`Applied Permission` of a :term:`User` amongst all of its existing :term:`Inherited Permissions`.


Permissions Resolution
------------------------

This section details the step-by-step process employed to resolve :term:`Effective Permissions` to grant or refuse
:term:`User` access to a given :term:`Resource`. Some of the steps also apply to :term:`Inherited Permissions`
resolution (see :term:`Extended Representation`_).

.. versionchanged:: 3.4
    Previous versions of `Magpie` would consider every :term:`Group` with equal priority (step (2.2) in below list),
    not making any distinction between them although there are usually some implied priorities in practice. Later
    versions include step (2.3) to remediate this issue.

Below are the resolution steps which are applied for every distinct :term:`Permission` ``name`` over a given
:term:`Resource` for which :term:`ACL` must be obtained:

1. Any :term:`Direct Permissions` applied explicitly for the evaluated :term:`User` and :term:`Resource` combination
   are obtained. Any such :term:`Permission`, whether it is affected by :attr:`Access.ALLOW` or :attr:`Access.DENY`
   modifier dictates the access result over that :term:`Resource`.

2. Following is the resolution of :term:`Inherited Permissions`. In this case, there are three possibilities:

    2.1 There is only one :term:`Group` for which a :term:`Permission` is defined. The :term:`User` inherits that
        specification, whether it is :attr:`Access.ALLOW` or :attr:`Access.DENY`.

    2.2 Many :term:`Group` membership exist and share of same highest priority. In this case, if any :term:`Group` has
        :attr:`Access.DENY`, the resolved access is marked as denied. If every equally prioritized :term:`Group`
        indicate :attr:`Access.ALLOW`, then access is granted to the :term:`User`.

    2.3 Otherwise, the highest priority :term:`Group` dictates the :class:`Access` resolution. This can
        *potentially revert* a previous :term:`Group` decision.


The specific use case of step (2.3) is intended to give higher resolution precedence to custom :term:`Groups` over the
special ``MAGPIE_ANONYMOUS_GROUP`` definition. This means that a custom :term:`Group` with a :term:`Permission` affected
by :attr:`Access.ALLOW` modifier can override special ``MAGPIE_ANONYMOUS_GROUP`` that would have :attr:`Access.DENY` for
the same :term:`Resource`, although resolution is opposite in every other situation. The reason for this exception is
due to the nature of ``MAGPIE_ANONYMOUS_GROUP`` membership that is being automatically applied to every :term:`User` in
order to also grant them `Public Access`_ to any :term:`Resource` marked as accessible to anyone. Since that special
:term:`Group` also represents *"unauthenticated users"*, it is both counter intuitive and not practical to equally
resolve conflicting :term:`Inherited Permissions` as it is naturally expected that an authenticated :term:`User` with
specific :term:`Group` memberships should receive higher access privileges than its unauthenticated counterpart in case
of contradictory :term:`Permissions` across both :term:`Group`. In other words, when a :term:`Resource` is blocked to
the open public, it is expected that a :term:`User` that would obtain access to that :term:`Resource` through another
one of its :term:`Group` memberships doesn't remain denied access due to its implicit ``MAGPIE_ANONYMOUS_GROUP``
membership. Step (2.3) handles this edge case specifically.

Every custom :term:`Group` share the same priority, and will therefore resolve conflicting :class:`Access` using the
normal step conditions and prioritizing :attr:`Access.DENY`.

When resolving only :term:`Inherited Permissions`, the procedure stops here and provides the applicable result if any
was found, with the corresponding ``reason``. An empty set of :term:`Permission` is returned if none could be found.

When instead resolving :term:`Effective Permissions`, the above process continues by rewinding the parent
:term:`Resource` hierarchy until the first :term:`Permission` is found. Only on the first iteration (when the targeted
:term:`Resource` is the same as the one looked for potential :term:`Inherited Permissions`) does :attr:`Scope.MATCH`
take effect. Only :attr:`Scope.RECURSIVE` are considered afterwards. When a :term:`Permission` is found, the process
immediately completes if :attr:`Access.DENY` results from the previous resolution steps. Otherwise, the process still
continues until reaching the top-most :term:`Service` to validate :attr:`Access.ALLOW` over the entire scope the
:term:`Permission` was found. If still no :term:`Permission` is defined after complete hierarchy processing, the result
defaults to :attr:`Access.DENY`, and indicated by ``"no-permission"`` reason.

.. todo: pseudo-code to represent the 'effective permission' portion of the resolution



.. seealso::
    - |perm_example_resolve|_

Examples
-------------------

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

Let's says we also got a ``example-user`` that is member of ``example-group``, and that  `Applied Permissions`_ on them
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

As illustrated, requesting for `Inherited Permissions`_ now also returns :term:`Group`-related :term:`Permission`
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
`Effective Permissions`_ always imply `Inherited Permissions`_ (i.e.: using both query simultaneously is redundant).
The reason why we obtain these sets for cases :sup:`(2)` is also because there is no other :term:`Permission` applied
to any of their parent :term:`Service` or :term:`Resource`. Contrarily, ``resource-A`` :sup:`(3)` now additionally
receives :term:`Permission` ``read`` indirectly from its parent ``service-2`` (note: ``write`` is redundant here).
Similarly, ``resource-B2`` :sup:`(4)` which did not even have any immediate :term:`Permission` applied to it,
now receives both ``read`` and ``write`` access, respectively from its parents ``resource-B1`` and ``service-3``. This
demonstrates why, although `Effective Permissions`_ imply `Inherited Permissions`_, they do not necessarily resolve to
the same result according to the effective :term:`Resource` hierarchy and its parent-children resolution implementation.

Using ``effective`` query tells `Magpie` to rewind the :term:`Resource` tree from the requested :term:`Resource` up to
the top-most :term:`Service` in order to accumulate all `Inherited Permissions`_ observed along the way for every
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

.. perm_example_modifiers:
.. |perm_example_modifiers| replace:: Permission Modifiers example

The effect of Permission Modifiers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
This will effectively grant ``UserA`` both of these permissions on ``Resource6``. Other ``access`` and ``scope``
concepts can only have one occurrence over same ``name`` combination on a given hierarchy item, as they would define
conflicting interpretation of :term:`Effective Permissions`.

The above example presents only the resolution of :term:`User` permissions. When actually resolving
:term:`Effective Permissions`, all :term:`Inherited Permissions` from its :term:`Group` memberships are also considered
in the same fashion. The :term:`Group` permissions complement definitions specifically applied to a :term:`User`.
In case of conflicting situations, such as when ``allow`` is applied via :term:`Direct Permissions`
and ``deny`` is defined via :term:`Inherited Permissions` for same :term:`Resource`, :term:`Direct Permissions` have
priority over any :term:`Group` :term:`Permission`. Also, ``deny`` access is prioritized over ``allow`` to preserve
the default interpretation of protected access control defined by `Magpie`. When ``match`` and ``recursive`` scopes
cause ambiguous resolution, the ``match`` :term:`Permission` is prioritized over inherited access via parent ``scope``.


.. perm_example_resolve:
.. |perm_example_resolve| replace:: Permission Resolution example

Resolution of Overlapping Permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. todo: permission resolution example with >2 group that contradict, >2 groups that have redundant (same) permissions
.. todo: permission resolution example with some Group ALLOW > anonymous DENY
.. todo: permission resolution example that includes simultaneously recursive/match, allow/deny and user/multi-group
