.. _glossary:
.. include:: references.rst

************
Glossary
************

.. glossary::
    :sorted:

    ACL
        Access Control List.
        Set of :term:`User` and :term:`Group` scopes, provided session :term:`Authentication` elements, that either
        grants or denies access to the applicable :term:`User` to the targeted HTTP request.

    Authentication
        Process of identifying one-self using credentials in order to login into `Magpie`, or retrieving connected
        session :term:`User` during an HTTP request using supported methods.

    Authorization
        Process of allowing or denying access to a :term:`Resource` or :term:`Service` according to :term:`Logged User`
        identified through :term:`Authentication` methods. This process typically falls into the hands of a
        :term:`Proxy` application.

    Cookies
        Set of :term:`Authentication` identifiers primarily employed by `Magpie` HTTP requests to determine the
        :term:`Logged User`.

    Direct Permission
        Describes a :term:`Permission` that originates directly from a :term:`Service`.
        See :ref:`direct permissions` details.

    Discoverable Group
        :term:`Group` that has property ``discoverable=True``, making it publicly viewable to any-level user.
        Otherwise, groups can be listed or accessed only by administrators.

    Effective Permission
        A :term:`Permission` that has been completely resolved according to all applicable contexts, that indicates
        the final granted or denied result. See also :ref:`effective permissions`.

    Group
        Entity on which :term:`Permission` over a :term:`Service` or :term:`Resource` can be applied. Any :term:`User`
        can be set as a member of any number of :term:`Group`, making it inherit all applicable set of
        :term:`Permission`.

    Inherited Permission
        Describes a :term:`Permission` that originates from a children :term:`Resource` under a :term:`Service`.
        See :ref:`inherited permissions` details.

    Logged User
        Specific :term:`User` that corresponds to the active request session. This :term:`User` can automatically be
        referenced to (instead of usual ``{user_name}`` path variable) in applicable requests using special value
        configured with :py:data:`magpie.constants.MAGPIE_LOGGED_USER`. When not logged in, this
        :term:`User` is considered to be :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`. Otherwise, it is whoever
        the :term:`Authentication` mechanism identifies.

    Permission
        Element that defines which rules are applicable for a given combination of :term:`User` and/or :term:`Group`
        against one or many :term:`Service` and/or :term:`Resource`. See `permissions`_ for more exhaustive details.
        Applicable values defined by enum :py:class:`magpie.permissions.Permission`.

    Proxy
        Sibling service (typically `Twitcher <Twitcher>`_) that employs `Magpie` as access management of :term:`User`,
        :term:`Group`, :term:`Service` and :term:`Resource` to obtain applicable sets of :term:`Permission`.
        Provided these, it acts as policy enforcement point (PEP).

    Public
        Refers to a :term:`Permission` applied on a :term:`Service` or :term:`Resource` to special elements in order
        to make them available to anyone including even unauthenticated sessions. See also :ref:`Public Access` section
        for implementation details to achieve this result.

    Resource
        Entity on which :term:`User` and :term:`Group` can be associated to applicable :term:`Permission` respectively
        for the contextual :term:`Service` under which it resides. This element can represent relatively *anything*.
        The interpretation of each :term:`Resource` depends on the context of the :term:`Service` they relate to.
        Implemented by sub-classes of :py:class:`magpie.models.Resource`.

    Service
        Top-level specialized :term:`Resource` that defines which children :term:`Resource` elements are applicable to
        it (if any), how its hierarchy of :term:`Resource` should behave against incoming HTTP request details, and how
        to parse any set of :term:`Permission` applied on them against respective request elements. Also defines URL
        connexion details pointing to the actual service on which access control are applicable. Each type of
        :term:`Service` defines different combination of functionalities. Implemented by sub-classes of
        :py:class:`magpie.models.ServiceInterface`.

    User
        Unitary entity containing details about the user allowing it to log into `Magpie` and that can have other
        relationships applied to it such as :term:`Permission` and :term:`Group` that extend his specific access rights
        to :term:`Service` and :term:`Resource` elements. Implemented by :py:class:`magpie.models.User`.


.. _permissions: permissions.rst

