.. include:: references.rst

.. _auth_methods:

Authentication and Authorization
==========================================

In order to perform :term:`Authentication` in `Magpie`, multiple :term:`Providers` and methods are supported.
By default, the :term:`Internal Provider` named ``ziggurat`` is employed, which corresponds to the package used
internally to manage all `Magpie` elements. Login procedure is covered in :ref:`Authentication Requests` section.

Supported :term:`External Providers` are presented in the table below in section :ref:`authn_providers`, although more
could be added later on.

.. note::
    Terms :term:`Authentication` :term:`Providers`, :term:`External Providers` and :term:`External Providers` in this
    chapter must not be confused with ``providers`` employed in :ref:`config_providers`. In this chapter, providers
    refer to user-identity resolvers, in contrast to :term:`Service` definitions from the configuration files.

.. _authn_requests:

Authentication Requests
---------------------------

The most convenient way to sign-in with `Magpie` is to employ the user interface provided on path
``{MAGPIE_URL}/ui/login``. This page will present fields that allow both :term:`Internal Provider` and
:term:`External Provider` login methods.

Alternatively, API requests can be employed to define your own interface, or to obtain request tokens needed to
accomplish further requests interactions toward `Magpie` or obtain :term:`Authorization` from the :term:`Proxy` using
`Magpie` to enforce policies.

Following are the supported request formats.

.. _authn_req_method:

Request Method
~~~~~~~~~~~~~~~

Both ``GET`` and ``POST`` are supported. This is in order to allow resolution of credentials for some
applications that do not correctly handle or purposely prohibit use of ``POST`` method. Also, ``GET`` helps quickly
accomplishing a login from a web browser using the ``{MAGPIE_URL}/signin`` endpoint with query parameters
(see :ref:`authn_login_query`).

.. note::
    Whenever possible, prefer ``POST`` request with :ref:`authn_login_body` or the UI endpoint.
    See also warning in :ref:`authn_login_query` for details.


.. _authn_login_query:

Query Parameters
~~~~~~~~~~~~~~~~~~~~

This method employs the query string parameters in the URL to provide the credentials. The format is as follows.

.. code-block::

    GET {MAGPIE_URL}/signin?user_name=<usr>&password=<pwd>


The response will contain :ref:`Authentication Headers` detail needed for user identification.


.. warning::
    Whenever possible, it is **strongly** recommended to instead use another one of the methods which offers
    better support for different ``Content-Type`` responses to interact with `Magpie` as an API.

    Furthermore, using the ``POST`` method with content body and/or headers reduces risks of credential leaks that
    would be visible in plain text via query parameters using ``GET`` request. Most servers and applications log path
    and query parameters profusely, or even caches them, which can lead to easier identity theft or hacking of servers.
    The ``GET`` method remains available for backward compatibility and quick testing purposes only.


.. _authn_login_body:

Body Content
~~~~~~~~~~~~~~~~~~~

Body content requests allow multiple variants, based on the specified ``Content-Type`` header.
All variants employ a similar structure, but indicate the format of the body to be parsed.
By default, ``application/json`` is employed if none was specified.

.. code-block::

    POST {MAGPIE_URL}/signin
    Headers
        Content-Type: multipart/form-data; boundary=<boundary-string>
    Body
        user_name: "<usr>"
        password: "<pwd>"
        provider_name: "<provider>"     # optional


.. code-block::

    POST {MAGPIE_URL}/signin
    Headers
        Content-Type: application/x-www-form-urlencoded
    Body
        user_name=<usr>&password=<pwd>&provider_name=<provider>


.. code-block::

    POST {MAGPIE_URL}/signin
    Headers
        Content-Type: application/json
    Body
        {
            "user_name": "<usr>",
            "password": "<pwd>",
            "provider_name": "<provider>"
        }


The response will contain :ref:`Authentication Headers` detail needed for user identification.


.. _authn_providers:

Authentication Providers
---------------------------

For any of the :term:`Authentication` requests, omitting the ``provider_name`` identifier
(or explicitly using value of :envvar:`MAGPIE_DEFAULT_PROVIDER`) will default to employ :term:`Internal Provider`
method. This means that :term:`User` identity resolution will be attempted against locally registered users in `Magpie`
database.

To instead use one of the :term:`External Providers`, the corresponding provider identifier must be provided within
the sign-in request contents with ``provider_name``. The value of that field must be one of the available provider in
the below table.

Each provider has different configuration parameters as defined in `Magpie Security`_ module and use various protocols
amongst ``OpenID``, ``ESGF``-flavored ``OpenID`` and ``OAuth2``. Further :term:`External Providers` can be defined
using this module's dictionary configuration style following parameter specification of `Authomatic`_ package used for
managing this :term:`Authentication` procedure.

+--------------------------------+-----------------------------------------------------------------------+
| Category                       | Provider                                                              |
+================================+=======================================================================+
| Open Identity (``OpenID``)     | `OpenID`_                                                             |
+--------------------------------+-----------------------------------------------------------------------+
| *Earth System Grid Federation* | *German Climate Computing Centre* (`DKRZ`_)                           |
| (`ESGF`_) :sup:`(1)`           |                                                                       |
|                                +-----------------------------------------------------------------------+
|                                | *French Research Institute for Environment Science* (`IPSL`_)         |
|                                +-----------------------------------------------------------------------+
|                                | *British Centre for Environmental Data Analysis* (`CEDA`_) :sup:`(2)` |
|                                +-----------------------------------------------------------------------+
|                                | *US Lawrence Livermore National Laboratory* (`LLNL`_) :sup:`(3)`      |
|                                +-----------------------------------------------------------------------+
|                                | *Swedish Meteorological and Hydrological Institute* (`SMHI`_)         |
+--------------------------------+-----------------------------------------------------------------------+
| ``OAuth2``                     | `GitHub_AuthN`_ Authentication                                        |
|                                +-----------------------------------------------------------------------+
|                                | `WSO2`_ Open Source Identity Server                                   |
+--------------------------------+-----------------------------------------------------------------------+

| :sup:`(1)` extended variant of ``OpenID``
| :sup:`(2)` formerly identified as *British Atmospheric Data Centre* (`BADC`_)
| :sup:`(3)` formerly identified as *Program for Climate Model Diagnosis & Intercomparison* (`PCMDI`_)

.. note::
    Please note that due to the constantly changing nature of multiple of these external providers (APIs and moved
    Websites), rarely used authentication bridges by the developers could break without prior notice. If this is the
    case and you use one of the broken connectors, summit a new `issue`_.

Using any of the :term:`External Providers` will tell `Magpie` to interrogate the configured identity URL of that
provider and use the credentials to attempt :term:`Authentication`. If successful, the response returned by that
:term:`Provider` should be parsed by `Magpie` in order to determine which corresponding local :term:`User` profile
it refers to. After validation, the :term:`Logged User` will be :term:`Authenticated` and following requests will be
applicable using the same ``Cookie`` methodology as when using normal local provider procedure.
See :ref:`Authentication Headers` for more details on that matter.


.. _authn_headers:

Authentication Headers
---------------------------

.. versionadded:: 3.9
    The ``WWW-Authentication`` and ``Location-When-Unauthenticated`` headers are returned whenever the
    HTTP ``Unauthorized [401]`` response is the result of a request. This is done in order to help requesting
    users or applications identify the endpoint where it can attempt :term:`Authentication` with credentials.


After execution of an :term:`Authentication` request, a ``Set-Cookie`` header with `Magpie` user identification token
named according to :ref:`config_security` should be set in the response as follows.

.. code-block::

    Set-Cookie: {MAGPIE_COOKIE_NAME}=<auth-token>!userid_type:int;
                [Domain=<domain>; Path=<path>; HttpOnly; SameSite=Lax; Max-Age=<seconds>; expires=<datetime>]

Web browsers and libraries for HTTP requests handling should automatically detect that header and register the defined
``Cookie`` for subsequent requests. Alternatively, that ``Cookie`` can be provided directly in the request using the
same format.

All additional parameters (in brackets above) are optional and can be provided to explain how control of the scope the
`Magpie` cookie applies to, notably to avoid conflicts with other potential cookies employed by the request. The only
mandatory parts are the :envvar:`MAGPIE_COOKIE_NAME` value, the actual token value, and the indication of represented
content with ``!userid_type:int`` to let `Magpie` known the provided token information is employed to resolve the
:term:`Logged User` by ID.

Note that any ``Cookie`` generated by `Magpie` can have a maximum valid duration, identified by the both the returned
``Max-Age`` in seconds and the ``expires`` value as explicit date and time. Generated cookies are defined in such a way
that they will automatically emit a new ``Cookie`` based on reissue time after 1/10th of the ``Max-Age`` to update the
``Cookie`` over continuous sessions. Any :term:`Logged User` will therefore remain logged in if further requests are
accomplished using the same ``Cookie`` within the lifetime duration of the original login, unless explicitly logged out.
Modifications of the duration is accomplished using configuration detailed in :ref:`config_security`.

.. versionchanged:: 3.9
    Although maximum duration could be defined in settings, prior versions did not explicitly indicate them in the
    generated ``Cookie``. Following versions without these values will effectively mean the ``Cookie`` has unlimited
    lifetime.


As for most of the other API request endpoints offered by `Magpie`, the ``Accept`` header can be provided to select the
format of the desired returned content. Following valid :term:`Authentication`, the body should contain a basic message
indicating as such, and returning ``OK [200]`` status. Otherwise, the appropriate HTTP error code will be returned with
a description message of the error cause. By default, header definition ``Accept: */*`` or completely omitted value for
``Accept`` will employ ``application/json`` for the returned ``Content-Type``.


.. _authz_headers:

Authorization Headers
---------------------------

Following any successful :term:`Authentication` request as presented in the previous section, the obtained ``Cookie``
defines which :term:`Logged User` attempts to accomplish an operation against a given protected URI. `Magpie` employs
the same ``Cookie`` both for operations provided by its API and for accessing the real :term:`Resource` protected
behind the :term:`Proxy` according to resolution of :term:`Effective Permissions` based on :term:`Applied Permissions`
definitions.

Access to Magpie Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a :term:`Logged User` has sufficient :term:`Permissions`, it will be allowed different levels of access to
operate onto `Magpie` API paths. The specific requirements for each case are extensively presented in section
:ref:`perm_route_access`.

Access to Protected Resources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When sending requests to the :term:`Policy Enforcement Point` (e.g.: `Twitcher`_ :term:`Proxy`),
appropriate ``Cookie`` headers must be defined for it to identify the :term:`Logged User` and resolve its
:term:`Effective Permissions` accordingly. Not providing those tokens will default to using
:envvar:`MAGPIE_ANONYMOUS_USER`, which will result into either one of HTTP ``Unauthorized [401]`` or
``Forbidden [403]``, depending on how the PEP interprets and returns the response indicated by `Magpie`, unless the
corresponding :term:`Resource` was allowed for :ref:`perm_public_access`.

When appropriately authenticated, access to the targeted :term:`Resource` will be granted or denied depending on the
:term:`Effective Permissions` that :term:`Logged User` has for it. This decision is extensively explained in section
:ref:`perm_resolution`.

Another alternative to obtain :term:`Authorization` (only when using the :ref:`utilities_adapter<Magpie Adapter>`) is
by providing the ``Authorization`` header in the request with appropriate credentials. In this situation, the adapter
will attempt a login operation inline to that original request, and if successful, will update the ``Cookie`` headers
accordingly. Although this method saves the need for the client to explicitly do an initial :term:`Authentication`
request toward `Magpie`'s signin path prior to :term:`Resource` access attempt, failing to update the following any
following requests with the ``Cookie`` will repeat the procedure on each call, which will slow down response time. If
multiple requests are executed, especially for accessing different protected resources, :ref:`authn_requests` should be
employed instead to process :term:`Authentication` only once.

The format of the ``Authorization`` header is has follows.

.. code-block::

    Authorization: Bearer <access_token>


Where the ``access_token`` must correspond with the applicable ``provider_name`` specified by query parameter in order
to orchestrate the :term:`Authentication` operation accordingly. Once again, omitting the ``provider_name`` will default
to :term:`User` identification against local accounts in `Magpie` using :envvar:`MAGPIE_DEFAULT_PROVIDER`.


.. fixme: https://github.com/Ouranosinc/Magpie/issues/255
.. todo::

    Support ``Authorization: Basic <base64-user-pass>`` (see `#255 <https://github.com/Ouranosinc/Magpie/issues/255>`_)
