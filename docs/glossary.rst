.. include:: references.rst
.. _glossary:

************
Glossary
************

.. glossary::
    :sorted:

    Access Permission
        Required :term:`Group` membership to obtain sufficient privileges in order to be permitted the execution of
        a given request. Requests under different scopes require variable access levels depending on context.

    Access Control Entry
    ACE

        Definition of an access control rule (or policy) with `Allow` or `Deny` decision for a given :term:`User` or
        :term:`Group` active according to a certain :term:`Permission` name and scope. Multiple :term:`ACE` form the
        effective :term:`ACL` conditions to be evaluated to either grant or refuse access (i.e.: to provide
        the :term:`Authorization` result based on the authenticated :term:`User`).

    Access Control List
    ACL

        Set of :term:`User` and :term:`Group` scopes, provided session :term:`Authentication` elements, that either
        grants or denies :term:`Permission` access to the applicable :term:`User` for the targeted :term:`Resource`.
        Formed of multiple :term:`ACE`.

    Allowed Permission
        Set of applicable :term:`Permission` values onto an element.

        .. seealso::
            :ref:`Allowed Permissions <allowed-permissions>` section for details.

    Application Programming Interface
    API
        Most typically, referring to the use of HTTP requests following an :ref:`OpenAPI` specification,
        and more broadly, to refer to `Magpie`'s own API definition. It can also refer to a specific :term:`Service`
        using RESTful API, which can be registered using the :ref:`ServiceAPI` implementation.

    Applied Permission
        An active :term:`Permission` for a given :term:`User` or :term:`Group` depending on context.

        .. seealso::
            :ref:`Applied Permissions <applied-permissions>` section for details.

    Authentication
        Process of identifying one-self using credentials in order to login into `Magpie`, or retrieving connected
        session :term:`User` during an HTTP request using supported methods.

        .. seealso::
            :ref:`auth_methods` section for details.

    Authorization
        Process of allowing or denying access to a :term:`Resource` or :term:`Service` according to :term:`Logged User`
        identified through one of the :ref:`Authentication Methods <auth_methods>`. This process typically falls into
        the hands of a :term:`Proxy` application as :term:`Policy Enforcement Point` using policy access decisions
        provided by `Magpie`.

    Context User
        Specific :term:`User` that is being targeted by a request from specified value for the ``{user_name}`` request
        path variable. The contextual :term:`User` of the request *could* correspond to the :term:`Logged User` if the
        reference resolves to itself, but this is not necessarily the case.

        .. seealso::
            :ref:`Route Access` for further details and examples provided.

    Cookies
        Set of :term:`Authentication` identifiers primarily employed by `Magpie` HTTP requests to determine the
        :term:`Logged User`.

    Direct Permissions
        Describes a :term:`Permission` that is given to a :term:`User` explicitly, rather than one of its :term:`Group`
        memberships.

        .. seealso::
            :ref:`Direct Permissions <direct_permissions>` section for details.

    Discoverable Group
        :term:`Group` that has property ``discoverable=True``, making it publicly viewable to any-level user.
        Otherwise, groups can be listed or accessed only by administrators.

    Effective Permission
        A :term:`Permission` that has been completely resolved according to all applicable contexts, that indicates
        the final granted or denied result.

        .. seealso::
            :ref:`Effective Permissions <effective_permissions>` section for details.

    Effective Resolution
        Process of resolving :term:`Effective Permission` over a :term:`Resource` considering any applicable
        :ref:`permission_modifiers`.

        .. seealso::
            :ref:`perm_resolution` section for details.

    External Providers
        Set of all known user-identity :term:`Provider` defined externally to `Magpie`. Each of these :term:`Provider`
        require specific connection methodologies, as configured in :mod:`magpie.security`.

        .. seealso::
            :ref:`authn_providers` section for details.

    Group
        Entity on which :term:`Permission` over a :term:`Service` or :term:`Resource` can be applied. Any :term:`User`
        can be set as a member of any number of :term:`Group`, making it inherit all applicable set of
        :term:`Permission`. A :term:`Group` can optionally have terms and conditions, which the :term:`User` has to
        accept before being assigned to the :term:`Group`. In this case, an email is sent to the :term:`User` upon
        request to ask for confirmation. The terms and conditions can only be defined upon the :term:`Group` creation
        and can never be modified afterwards.

    Immediate Permission
        Describes a :term:`Permission` that originates directly and only from a :term:`Service`.
        This is referenced in only a few use-cases, notably for :ref:`Finding User Permissions`.

        .. seealso::
            :ref:`Immediate Permissions <immediate_permissions>` section for details.

    Inherited Permission
        Describes a :term:`Permission` that includes both :term:`User` and :term:`Group` contexts simultaneously.

        .. seealso::
            :ref:`Inherited Permissions <inherited_permissions>` section for details.

    Internal Providers
        Represents all the :term:`Provider` that are known for *local* (instead of *external*)
        :term:`Authentication` to the referenced `Magpie` instance. The credentials for login as locally searched
        fo rather than dispatched to an external user-identity. For the moment, this consists uniquely of
        :py:data:`magpie.constants.MAGPIE_DEFAULT_PROVIDER` constant.

    Logged User
        More specific use-case of :term:`Request User` that simultaneously corresponds to the active request session
        :term:`User` as well at the referenced :term:`Context User` from the path variable. This :term:`User` can be
        automatically retrieved in applicable requests using in the request path the special constant value defined by
        :py:data:`magpie.constants.MAGPIE_LOGGED_USER`, or using its literal :term:`User` name.
        When not logged in, this :term:`User` is considered to be equivalent to explicitly requesting
        :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`. Otherwise, it is whoever the
        :term:`Authentication` mechanism identifies with token extracted from request :term:`Cookies`.

    Network Node
        A reference to an instance of the Magpie software within a network of Magpie instances. Each Magpie instance
        within the network is registered in the database as a row in the ``network_nodes`` table. Each node is
        represented by a name that is unique across all nodes in the network, and a url that is used to send http
        requests to that specific node.

    Network Token
        A unique random string that can be used to authenticate a user as part of the :ref:`Network Mode` authentication
        procedure.

    OpenAPI
    OAS
        The |OpenAPI-spec|_ (`OAS`) defines a standard, programming language-agnostic interface description for
        HTTP :term:`API`s. It is used in `Magpie` to represent :term:`API` definitions for requests and responses.

    OGC
        Acronym for `Open Geospatial Consortium` that represent the global initiative and community to standardize
        geospatial data and service methodologies in order to improve access to geospatial and location information.

    OWS
        Acronym that regroups all :term:`OGC` Web Services. This includes :term:`Web Feature Service <WFS>` (WFS),
        :term:`Web Map Service <WMS>` (WMS) and :term:`Web Processing Service <WMS>` (WPS), amongst others, for which
        `Magpie` offers some specific :term:`Service` request parser implementations.

    Pending User
        Account that is pending for validation or approval following self-registration when the application is
        configured to provide that functionality.

        .. seealso::
            :ref:`user_registration` section for further details about the self-registration procedure.

    Permission
        Element that defines which rules are applicable for a given combination of :term:`User` and/or :term:`Group`
        against one or many :term:`Service` and/or :term:`Resource`, depending of the many contexts for which they
        can apply. Applicable values are generally defined by enum :py:class:`magpie.permissions.Permission`.

        .. seealso::
            :ref:`permissions` chapter provides more exhaustive details,
            including contextual comparisons for all other *Permission*-related terms presented here.

    Policy Decision Point
    PDP

        Application that has the responsibility to take the decision whether or not to allow or deny access of a given
        :term:`User` to some targeted :term:`Resource` based on applicable :term:`Permission` rules. This is the role
        that `Magpie` fulfills.

    Policy Enforcement Point
    PEP

        Application that has the responsibility of applying the decision provided by the :term:`PDP` in order to grant
        access or block access to the :term:`Resource` by the intended :term:`User`. This is typically accomplished by
        `Twitcher`_ :term:`Proxy`, but can be implemented by any application that can communicate with `Magpie` through
        the API endpoint it provides.

    Provider
        Corresponds to the reference user-identity to employ in order to attempt :term:`Authentication`.
        Identities are regrouped either as :term:`Internal Providers` or :term:`External Providers`.

        .. seealso::
            ref:`authn_providers` section for details.

    Proxy
        Sibling service (typically `Twitcher`_) that employs `Magpie` as access management of :term:`User`,
        :term:`Group`, :term:`Service` and :term:`Resource` to obtain applicable sets of :term:`Permission`.
        Provided these, it acts as :term:`Policy Enforcement Point`.

    Public
        Refers to a :term:`Permission` applied on a :term:`Service` or :term:`Resource` to special elements in order
        to make them available to anyone including even unauthenticated sessions.

        .. seealso::
            :ref:`Public Access` section for implementation details to achieve this result.

    Request User
        Active HTTP request session :term:`User` that can be retrieved by calling ``request.user`` with resolution of
        :term:`Authentication` headers within the request (:term:`User` is ``None`` if unauthenticated,
        i.e.: :py:data:`magpie.constants.MAGPIE_ANONYMOUS_USER`). This is not the same as the :term:`Context User`
        extracted from ``{user_name}`` path variable, except for the special case covered by :term:`Logged User`'s
        definition. The request :term:`User` could send request that work on another :term:`Context User` than itself
        if sufficient :term:`Access Permission` is granted.

        .. seealso::
            :ref:`Route Access` for further details.

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

    Service Hook
        Plugin function handler that can apply modifications onto received requests or returned responses when
        interacting with `Twitcher`_ :term:`Proxy`, based on a set of filter conditions.

        .. seealso::
            :ref:`Service Hooks` section for details.

    User
        Unitary entity containing details about the user allowing it to log into `Magpie` and that can have other
        relationships applied to it such as :term:`Permission` and :term:`Group` that extend his specific access rights
        to :term:`Service` and :term:`Resource` elements. Implemented by :py:class:`magpie.models.User`.

    Webhook
        Subscribable events handlers to send HTTP(S) requests following the occurrence of a given `Magpie` action.

        .. seealso::
            :ref:`config_webhook` and :ref:`config_file` sections for details.

    Web Feature Service
    WFS

        One of the :term:`OWS` implementation which `Magpie` offers an implementation
        for controlling access to layers and their features.

    Web Map Service
    WMS
        One of the :term:`OWS` implementation which `Magpie` offers an implementation
        for controlling access to layers and generated maps from them.

    Web Processing Service
    WPS
        One of the :term:`OWS` implementation which `Magpie` offers an implementation
        for controlling access to description and execution of processes.
