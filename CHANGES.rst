.. explicit references must be used in this file (not references.rst) to ensure they are directly rendered on Github
.. :changelog:

Changes
*******

`Unreleased <https://github.com/Ouranosinc/Magpie/tree/master>`_ (latest)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``type`` query parameter to multiple requests returning ``Services`` or ``Resources`` regrouped by ``ServiceType``
  to limit listing in responses and optimise some operations where only a subset of details are needed. Using this
  feature, some ``Permissions`` listing in UI pages are faster because ``Services`` not required since they are not
  being displayed are skipped entirely, removing the need to compute their underlying ``Resource`` and ``Permissions``
  tree hierarchy.

`3.15.1 <https://github.com/Ouranosinc/Magpie/tree/3.15.1>`_ (2021-09-29)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add multiple new log entries during ``Permission`` effective resolution and ``Service`` retrieval
  within ``MagpieAdapter`` to debug procedure and attempt identifying any problem with it when caching is involved
  (relates to `#466 <https://github.com/Ouranosinc/Magpie/issues/466>`_).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Pin ``sqlalchemy``, ``sqlalchemy_utils``, ``zope.sqlalchemy`` and ``ziggurat_foundations`` to specific package
  versions to avoid underlying issues when combining dependencies with `Twitcher` (in ``Docker.adapter``).
  Some definitions at lower level in ``ziggurat_foundations`` cause an issue when moving to ``sqlalchemy>=1.4``,
  which was allowed since `Twitcher` ``v0.5.5``
  (see `ergo/ziggurat_foundations#71 <https://github.com/ergo/ziggurat_foundations/issues/71>`_).
  It is temporarily addressed by reducing requirements of `Twitcher`
  (see `bird-house/twitcher#108 <https://github.com/bird-house/twitcher/pull/108>`_) and referencing its associated
  release ``v0.5.6`` in the ``Docker.adapter``, which downgrades needed packages when extending it with `Magpie`.
* Use ``pip`` legacy and faster resolver as per
  `pypa/pip#9187 (comment) <https://github.com/pypa/pip/issues/9187#issuecomment-853091201>`_
  since current one is endlessly failing to resolve development packages (linting tools from ``check`` targets).
* Add possible detached ``Resource`` reconnection (``merge``) to active session during ``Permission`` effective
  resolution with mixed caching state between `ACL` and `Service` regions in case they mismatch
  (potential fix to `#466 <https://github.com/Ouranosinc/Magpie/issues/466>`_).

`3.15.0 <https://github.com/Ouranosinc/Magpie/tree/3.15.0>`_ (2021-08-11)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Improve API update operation of ``Service`` for allowed fields in order to accept body containing only the
  new value for the custom ``configuration`` without additional parameters. It was not possible to
  update ``configuration`` by itself, as ``service_name`` and ``service_url`` were independently validated
  for new values beforehand.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix lookup error of setting ``MAGPIE_USER_REGISTRATION_ENABLED`` when omitted from configuration during
  user email update (fixes `#459 <https://github.com/Ouranosinc/Magpie/issues/459>`_).
* Fix erasure value ``None`` (JSON ``null``) validation when updating ``Service`` field ``configuration`` to
  properly distinguish explicitly provided ``None`` against default value when the field is omitted.
* Fix incorrect OpenAPI body schema indicated in response of ``POST /services`` request.

`3.14.0 <https://github.com/Ouranosinc/Magpie/tree/3.14.0>`_ (2021-07-14)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Improve error reporting of ``MagpieAdapter`` when validating the *requested* ``Permission``. If the `Service`
  implementation raises an ``HTTP Bad Request [400]`` due to insufficient, invalid or missing parameters from
  the request to properly resolve the corresponding `Magpie` ``Permission``, more details about the cause will
  be reported in the `Twitcher` response body. Also, code ``400`` is returned instead of ``500``
  (relates to `#433 <https://github.com/Ouranosinc/Magpie/issues/433>`_).
* Improve caches invalidation of computed `ACL` permissions following corresponding `Service` cache invalidation.
* Enforce disabled caching of ``service`` and ``acl`` regions if corresponding settings where not provided
  in INI configuration files of both `Magpie` and `Twitcher` (via ``MagpieAdapter``).
* Add more tests that validate invalidation and resolution behaviours of caching.
* Add test that validates performance speedup caching provides when enabled.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* | Fix an issue in ``MagpieAdapter`` when `Service` caching is enabled (in `Twitcher` INI configuration) that caused
    implementations derived from ``ServiceOWS`` (WPS, WMS, WFS) to incorrectly retrieve and parse the cached request
    parameters instead of the new ones from the incoming request.
  |
  | **SECURITY**:
  | Because ``ServiceOWS`` implementations employ request parameter ``request`` (in query or body based on HTTP method)
    to infer their corresponding `Magpie` ``Permission`` (e.g.: ``GetCapabilities``, ``GetMap``, etc.), this produced
    potential inconsistencies between the *requested* ``Permission`` that `Twitcher` was evaluating with `Magpie`, and
    the *actual request* sent to the `Service` behind the proxy. Depending on the request order and cache expiration
    times, this could lead to permissions incorrectly resolved for some requests, granting or rejecting wrong user
    access to resources.

`3.13.0 <https://github.com/Ouranosinc/Magpie/tree/3.13.0>`_ (2021-06-29)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Changed ``UserStatuses.WebhookErrorStatus = 0`` to ``UserStatuses.WebhookError = 2`` to provide further
  functionalities. Migration script applies this change to existing ``User`` entries.
* Changed the returned ``status`` value by the API routes to use the string name representation instead of the integer.
* Changed ``status`` search query handling of ``GET /users`` path for improved search and filtering capabilities.
* Add new ``UserStatuses.Pending = 4`` value that can be queried by administrators.
* Add ``UserPending`` object with corresponding table for pending approval by an administrator for some new
  self-registered user. Migration script creates the table with expected fields.
* Add new requests under ``/register/users`` and ``/ui/register/users`` endpoints for user account self-registration.
* Add UI view to display pending user registration details.
* Add UI icon to indicate when a listed user is pending registration approval or email validation.
* Disable user email self-update (when not administrator) both on the API and UI side
  whenever ``MAGPIE_USER_REGISTRATION_ENABLED`` was activated to avoid losing the confirmation of the original email
  (see feature `#436 <https://github.com/Ouranosinc/Magpie/issues/436>`_).
* Add configuration setting ``MAGPIE_USER_REGISTRATION_ENABLED`` to control whether user account self-registration
  feature should be employed.
  With it comes multiple other ``MAGPIE_USER_REGISTRATION_<...>`` settings to customize notification emails.
* Add multiple ``MAGPIE_SMTP_<...>`` configuration settings to control connections to notification email SMTP server.
* Add ``empty_missing`` flag to ``get_constant`` utility to allow validation against existing environment variables or
  settings that should be considered as invalid when resolved value is an empty string.
* Add missing ``format`` for applicable ``url`` and ``email`` elements in the OpenAPI specification.
* Add better logging options control in CLI operations.
* Add new CLI helper ``send_email`` to test various email template generation and SMTP configurations to send emails.
* Replace ``-d`` option of ``register_providers`` CLI operation (previously used to select database mode)
  by ``--db`` to avoid conflict with logging flags.
* Replace ``-d`` and ``-l`` options of ``batch_update_users`` CLI operation respectively by ``-D`` and ``-L``
  to avoid conflict with logging flags.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* | Explicitly disallow duplicate email entries, both with pre-validation and literal database values.
    Note that any duplicate email will be raised an migration script will fail. Manual cleanup of the undesired entry
    will be required, as `Magpie` will not be able to assume which one corresponds to the valid user to preserve.
  |
  | **SECURITY**:
  | Since email can be employed as another mean of login credential instead of the more typically used username,
    this caused potential denial of authentication for some user accounts where email was matched against another
    account with duplicate email.
* Add ``ziggurat_foundations`` extensions for Pyramid directly in the code during application setup such that an INI
  configuration file that omits them from ``pyramid.include`` won't cause `Magpie` to break.
* Define the various constants expected by GitHub as WSO2 external identity connectors with defaults to avoid
  unnecessary log warnings when calling CLI helper.

`3.12.0 <https://github.com/Ouranosinc/Magpie/tree/3.12.0>`_ (2021-05-11)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add explicit typing definitions of configuration files and resolved settings to facilitate discovery of invalid
  handling of formats or parameters during parsing and startup registration.
* Apply many documentation updates in both configuration sections and the corresponding configuration example headers.
* Add ``MAGPIE_WEBHOOKS_CONFIG_PATH`` configuration setting / environment variable that allows potentially using
  multiple configuration files for `Webhooks`. This parameter is notably important for developers that where using the
  ``MAGPIE_PROVIDERS_CONFIG_PATH`` or ``MAGPIE_PERMISSIONS_CONFIG_PATH`` settings to load multiple files, as they
  cannot be combined with single configuration provided by ``MAGPIE_CONFIG_PATH``, which was the only supported way to
  provide `Webhooks` definitions.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``users`` and ``groups`` registration configurations not respecting update method when conflicting
  definitions occur. They will respect alphabetical file name order and later ones remain.
* Fix ``users`` and ``groups`` registration configurations not correctly parsed when multiple files where employed
  (fixes `#429 <https://github.com/Ouranosinc/Magpie/issues/429>`_).
* Fix inappropriate validation of ``payload`` field when loading `Webhooks`.
  Empty ``{}``, ``""``, ``null`` payloads, or even omitting the parameter itself, will now be allowed since this
  can be valid use cases when sending requests without any body.
* Fix ``url`` parameter of `Webhooks` not allowing empty string for path portion of the URL.
* Fix incorrect documentation of ``name`` parameter handling for `Webhooks` in configurations files (single or multiple)
  with respect to the code. Duplicate entries are not enforced, but will be warned in logs.

`3.11.0 <https://github.com/Ouranosinc/Magpie/tree/3.11.0>`_ (2021-05-06)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add UI icons for `locked` and `delete` button operations on ``Users``, ``Groups`` and ``Services`` pages.
* Add ``detail`` query parameter to obtain user details from ``GET /users`` to avoid individual requests for each
  user when those information are needed (fixes `#202 <https://github.com/Ouranosinc/Magpie/issues/202>`_).
* Add the missing ``status`` and ``user_id`` fields in API schema of returned ``User`` responses.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix issue related to parsing cookies identified while submitting user creation from UI
  (fixes `#427 <https://github.com/Ouranosinc/Magpie/issues/427>`_).
  Added corresponding test (relates to `#193 <https://github.com/Ouranosinc/Magpie/issues/193>`_).

`3.10.0 <https://github.com/Ouranosinc/Magpie/tree/3.10.0>`_ (2021-04-12)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* | Update ``gunicorn>=20.x`` to receive latest security patches
    (fixes `#410 <https://github.com/Ouranosinc/Magpie/issues/410>`_).
  |
  | **IMPORTANT**:
  | Because ``gunicorn`` changed how its CLI handles INI files, ``pserve`` should be employed instead to ensure the
    configured web application port is properly applied with the provided ``magpie.ini`` configuration file.
    Furthermore, the (``host``, ``port``) or ``bind`` should be updated to employ ``0.0.0.0:2001`` instead of
    ``localhost:2001``, or any other combination of desired port to serve the application.

* Modify `Webhook` template variables to employ double braces (i.e.: ``{{<variable>}}``) to avoid ambiguity during
  parsing by YAML configuration files. Also employ dotted notation (e.g.: ``{{user.name}}``) to better represent which
  parameters come from a given entity.
* Update documentation to provide further details about `Webhook` configuration, examples and resulting event requests.
* Add `Webhook` implementations for ``User`` status update operation.
* Add `Webhook` implementations for every combination of ``User``/``Group``, ``Service``/``Resource``,
  creation/deletion operation of a ``Permission``.
* Add ``Permission`` tag to applicable OpenAPI schemas to regroup them and facilitate retrieving their operations that
  were otherwise scattered around in the various ``User``/``Group``, ``Service``/``Resource`` sections, amongst their
  already crowded listing.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix an edge case where `Webhook` template replacement could sporadically raise an error according to the replaced
  value not being a string.
* Fix default ``MAGPIE_PORT`` value not applied and validate other parsing resolution order for any environment
  variable or settings that can interact with ``MAGPIE_URL`` definition
  (resolves `#417 <https://github.com/Ouranosinc/Magpie/issues/417>`_).
* Fix OpenAPI schema definitions to employ the cookie authenticated security scheme when doing ``/users/...`` requests.
  Although *some* requests are public (i.e.: getting items related to ``MAGPIE_ANONYMOUS_USER``), every other request
  do require authentication, and is the most common method that the API is employed.

`3.9.0 <https://github.com/Ouranosinc/Magpie/tree/3.9.0>`_ (2021-04-06)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add missing ``WWW-Authentication`` and ``Location-When-Unauthenticated`` headers when HTTP ``Unauthorized [401]``
  response is returned (addresses `#96 <https://github.com/bird-house/twitcher/issues/96>`_ and
  fixes `#330 <https://github.com/Ouranosinc/Magpie/issues/330>`_).
* Add documentation details about ``Authentication`` and ``Authorization`` methods
  (fixes `#344 <https://github.com/Ouranosinc/Magpie/issues/344>`_).
* Change the default provider employed with ``Authorization`` header by the ``MagpieAdapter`` to match the default
  internal login operation applied when using the normal sign-in API path.
* Change the query ``provider`` to ``provider_name`` when using the ``Authorization`` header in order to aligned with
  ``provider_name`` employed for every other sign-in related operation.
* Ensure ``MagpieAdapter`` returns the appropriate code (``Unauthorized [401]`` vs ``Forbidden [403]``) according to
  missing or specified authentication headers.
* Forbid ``anonymous`` special user login as it corresponds to *"not logged in"* definition.
* Change HTTP ``Forbidden [403]`` responses during login to generic ``Unauthorized [401]`` to avoid leaking details
  about which are valid and invalid user names. Any failure to login using correctly formatted credentials will be
  errored out indistinctly as ``Unauthorized [401]``.
* Add API user ``status`` update operation using ``PATCH`` request (admin-only).
* Add API user list ``status`` to filter query by given user account statuses.
* Add UI icon to provide user status feedback on individual user info page and through user list summary.
* Change ``tmp_url`` to ``callback_url`` for `Webhook` template and provided parameter to `Webhook` requests to better
  represent its intended use.
* Improve `Webhook` template replacement to allow specification of ``format`` (default ``json``) and preserve non-string
  parameters following replacement. Other content-types will enforce string of the whole body.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Add missing ``Max-Age`` and ``expires`` indications in generated ``Cookie`` when ``MAGPIE_COOKIE_EXPIRE`` is defined.
* Fix incorrect metadata and format of response from login using ``GET`` method with contents generated by dispatched
  ``POST`` request.

`3.8.0 <https://github.com/Ouranosinc/Magpie/tree/3.8.0>`_ (2021-03-29)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Explicitly require ``MAGPIE_ADMIN_USER`` and ``MAGPIE_ADMIN_PASSWORD`` to be updated through configuration and
  application restart. Update is forbidden through the API and UI.
* Add UI loading animation while sync operation is in progress to indicate some user feedback that it was registered
  and is running until completion as it can take a while to parse all remote resources (depends on amount and latency).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix incorrect migration operation of old permission names to new permission-set scheme introduced in
  (`PR#353 <https://github.com/Ouranosinc/Magpie/issues/353>`_, database revision ``a2a039e2cff5``) that were omitting
  check of affected user/group, causing inconsistent drop of mismatching permissions. Resolution is retroactively
  compatible for every `Magpie` ``1.x → 2.x`` migration
  (fixes `#403 <https://github.com/Ouranosinc/Magpie/issues/403>`_).
* Fix UI erroneously displaying edit or delete operations for reserved user names that does not apply for such updates.
* Fix UI not handling returned error related to forbidden operation during user edition
  (identified by issue `#402 <https://github.com/Ouranosinc/Magpie/issues/402>`_).
* Fix password update of pre-registered administrator upon configuration change of ``MAGPIE_ADMIN_PASSWORD`` without
  modification to ``MAGPIE_ADMIN_USER`` (fixes `#402 <https://github.com/Ouranosinc/Magpie/issues/402>`_).
* Apply backward compatibility fixes to handle regexes in Python 3.5 (pending deprecation).
* Remove ``MagpieAdapter`` from Python 2.7 test suite to get passing results against obsolete version and unsupported
  code by `Twitcher`.
* Fix default value resolution of ``MAGPIE_CONFIG_DIR`` if the specified value is parsed as empty string.
* Fix mismatching resolution of database URL from different locations because of invalid settings forwarding.
* Patch broken sync ``RemoteResource`` due to invalid resolution of ziggurat-foundations model in tree generator
  (relates to `ergo/ziggurat_foundations PR#70 <https://github.com/ergo/ziggurat_foundations/pull/70>`_,
  fixes `#401 <https://github.com/Ouranosinc/Magpie/issues/401>`_).

`3.7.1 <https://github.com/Ouranosinc/Magpie/tree/3.7.1>`_ (2021-03-18)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Pin version of ``sqlalchemy<1.4`` breaking integrations with ``sqlalchemy_utils`` and ``zope.sqlalchemy``.

`3.7.0 <https://github.com/Ouranosinc/Magpie/tree/3.7.0>`_ (2021-03-16)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Introduce caching of ``Service`` definitions using ``beaker``, which can be use in conjunction with ``ACL`` caching
  to improve performance of `Twitcher` requests.
* Apply cache invalidation when it can be resolved upon changes to instances that should be reflected immediately.
* Update performance docs and INI related to caching.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Improve error message in case of failure to load INI file instead of misleading index error.
* Fix broken link to remote authentication provider in documentation.
* Fix JSON rendering of ``Group`` response specifically for ``MAGPIE_ADMIN_GROUP`` where ``inf`` value could not
  be converted. Literal string ``"max"`` is instead returned in that case, and the corresponding ``int`` for others.
* Fix conversion of ``expire`` value to integer when retrieved from ``MAGPIE_TOKEN_EXPIRE`` setting as string.

`3.6.0 <https://github.com/Ouranosinc/Magpie/tree/3.6.0>`_ (2021-02-09)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add a list of `Webhook` URLs, defined in the configuration, that will be called when creating or deleting a user
  (resolves `#343 <https://github.com/Ouranosinc/Magpie/issues/343>`_).

`3.5.1 <https://github.com/Ouranosinc/Magpie/tree/3.5.1>`_ (2021-02-08)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add URL endpoint to receive temporary tokens to complete pending operations
  (in preparation of PR `#378 <https://github.com/Ouranosinc/Magpie/issues/378>`_).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix rendering of path parameter details within OpenAPI schemas.
* Fix ``alembic`` migration failing due to new version updates of package
  (see `diff 1.4.3 => 1.5.2 <https://github.com/sqlalchemy/alembic/compare/rel_1_4_3..rel_1_5_2>`_).
* Fix documentation references and generation with updated Sphinx extension packages.
* Bump version of ``Twitcher`` to ``v0.5.5`` to obtain its Docker dependency fixes
  (see PR `bird-house/twitcher#99 <https://github.com/bird-house/twitcher/pull/99>`_).

`3.5.0 <https://github.com/Ouranosinc/Magpie/tree/3.5.0>`_ (2021-01-06)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``Group`` priority to resolve inherited permission resolution in case of multiple entries from different
  group memberships of the evaluated ``User``.
* Add ``reason`` field to returned ``Permission`` objects to help better comprehend the provenance of a composed
  set of permissions from ``User`` and its multiple ``Group`` memberships.
* Make *special* ``MAGPIE_ANONYMOUS_GROUP`` have less priority than other *generic* ``Group`` to allow reverting
  public ``DENY`` permission by one of those more specific ``Group`` with ``ALLOW`` permission.
* Simplify and combine multiple permission resolution steps into ``PermissionSet.resolve`` method.
* Resolve permissions according to *closest* ``Resource`` scope against applicable priorities.
* Update documentation with more permission resolution concepts and examples.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix invalid submission of ``Group`` memberships from ``User`` edit UI page to ignore ``MAGPIE_ANONYMOUS_GROUP``
  presence or omission since it cannot be edited regardless (blocked by API).
* Fix session retrieval in case of erroneous cookie token provided in request and not matching any valid ``User``.
  This could happen in case of previously valid ``User`` token employed right after it got deleted, making
  corresponding ID unresolvable until invalidated by timeout or forgotten, or by plain forgery of invalid tokens.
* Fix returned ``Group`` ID in response from creation request. Value was ``None`` and required second request to get
  the actual value. The ID is returned immediately with expected value.

`3.4.0 <https://github.com/Ouranosinc/Magpie/tree/3.4.0>`_ (2020-12-09)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add option to delete the ``User``'s own account.
* Add ``MAGPIE_TEST_VERSION`` to control (override) the local version to consider against test `safeguards`.
  Allows development of *future* versions using ``MAGPIE_TEST_VERSION=latest``.
* Add documentation about testing methodologies and setup configuration.
* Bump version of ``Twitcher`` to ``v0.5.4`` to provide Docker image with integrated ``MagpieAdapter`` using
  performance fix (see PR `bird-house/twitcher#98 <https://github.com/bird-house/twitcher/pull/98>`_).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix inconsistent UI spacing of *tabs* for panel selector and employ mako function to avoid duplicated code fragments.

`3.3.0 <https://github.com/Ouranosinc/Magpie/tree/3.3.0>`_ (2020-11-25)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add better details of HTTP error cause in returned UI page
  (resolves `#369 <https://github.com/Ouranosinc/Magpie/issues/369>`_).
* Ensure that general programming internal errors are not bubbled up in UI error page.
* Add function to parse output body and redact potential leaks of flagged fields.
* Align HTML format and structure of all edit forms portions of ``Users``, ``Groups`` and ``Services`` UI pages to
  simplify and unify their rendering.
* Add inline UI error messages to ``User`` edition fields.
* Improve resolution of `Twitcher` URL using ``TWITCHER_HOST`` explicitly provided  setting (or environment variable)
  before falling back to default ``HOSTNAME`` value.
* Employ `Pyramid`'s local thread registry to resolve application settings if not explicitly provided to
  ``magpie.constants.get_constant``, avoiding inconsistent resolution of setting value versus environment variable
  wherever the settings container was not passed down everywhere over deeply nested function calls.
* Handle `Twitcher`, `PostgreSQL` and `Phoenix` setting prefix conversion from corresponding environment variable names.
* Store custom configuration of ``Service`` into database for same definition retrieval between `Magpie` and `Twitcher`
  without need to provide the same configuration file to both on startup.
* Update ``Service`` registration operations at startup to update entries if custom configuration was modified.
* Update API to allow POST and PATCH operations with ``Service`` custom configuration.
* Display custom ``Service`` configuration as JSON/YAML on its corresponding UI edit page when applicable.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix validation of edited user fields to handle and adequately indicate returned error on UI
  (resolves `#370 <https://github.com/Ouranosinc/Magpie/issues/370>`_).

`3.2.1 <https://github.com/Ouranosinc/Magpie/tree/3.2.1>`_ (2020-11-17)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix incorrect flag that made some registration unittests to be skipped.
* Fix parsing of JSON and explicit string formatted permissions during their registration from configuration files.
* Update ``config/permissions.cfg`` documentation about omitted ``type`` field.

`3.2.0 <https://github.com/Ouranosinc/Magpie/tree/3.2.0>`_ (2020-11-10)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``catalog`` specific pattern by default for metadata ``BROWSE`` access of top-level ``ServiceTHREDDS`` directory.
  This resolves an issue where THREDDS accessed as ``<PROXY_URL>/thredds/catalog.html`` for listing the root directory
  attempted to compare ``catalog.html`` against the format-related *prefix* that is normally expected at this sub-path
  position (``<PROXY_URL>/thredds/catalog/[...]/catalog.html``) during children resource listing.
* Added pattern support for ``prefixes`` entries of ``ServiceTHREDDS``.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Adjust visual alignment of UI notices on individual newlines when viewing user inherited permissions.

`3.1.0 <https://github.com/Ouranosinc/Magpie/tree/3.1.0>`_ (2020-10-23)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``BROWSE`` permission for ``ServiceTHREDDS`` to parse request against *metadata* or *data* contents according to
  specified configuration of the specific service (resolves `#361 <https://github.com/Ouranosinc/Magpie/issues/361>`_).
* Add documentation details about parsing methodologies, specific custom configurations and respective usage of the
  various ``Service`` types provided by `Magpie`.
* Adjust ``MagpieAdapter`` such that ``OWSAccessForbidden`` is raised by default if the ``Service`` implementation fails
  to provide a valid ``Permission`` enum from ``permission_requested`` method. Incorrectly defined ``Service`` will
  therefore not unexpectedly grant access to protected resources. Behaviour also aligns with default ``DENY`` access
  obtained when resolving effective permissions through `Magpie` API routes.

* | Upgrade migration script is added to duplicate ``BROWSE`` permissions from existing ``READ`` permissions on every
    ``ServiceTHREDDS`` and all their children resource to preserve previous functionality where both *metadata* and
    *data* access where both managed by the same ``READ`` permission.
  |
  | **WARNING**:
  | Downgrade migration drops every ``BROWSE`` permission that could exist in later versions. This is done like so
    to avoid granting additional access to some ``THREDDS`` directories or file if only ``BROWSE`` was specified.
    When doing downgrade migration, ensure to have ``READ`` where both *metadata* and *data* should be granted access.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix parsing of ``ServiceAPI`` routes during retrieval of the deepest *available* ``Resource`` to ensure that even when
  the targeted ``Resource`` is actually missing, the *closest* parent permissions with ``Scope.RECURSIVE`` will still
  take effect. Same fix applied for ``ServiceTHREDDS`` for corresponding directory and file typed ``Resource``.
* Propagate SSL verify option of generated service definition if provided to `Twitcher` obtained from ``MagpieAdapter``.
* Adjust and validate parsing of ``ServiceWPS`` request using ``POST`` XML body
  (fixes `#157 <https://github.com/Ouranosinc/Magpie/issues/157>`_).

`3.0.0 <https://github.com/Ouranosinc/Magpie/tree/3.0.0>`_ (2020-10-19)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Adjust ``alembic`` migration scripts to employ date-ordered naming convention to help searching features within them.
* Add ``DENY`` permission access concept with new ``PermissionSet`` object and ``Access`` enum
  (resolves `#235 <https://github.com/Ouranosinc/Magpie/issues/235>`_).
* Remove ``-match`` suffixed entries from ``Permission`` enum in favor of new ``Scope`` enum employed by
  new ``PermissionSet`` definition.
* Update permission entries to employ explicit string representation as ``[name]-[access]-[scope]`` in the database
  (resolves `#342 <https://github.com/Ouranosinc/Magpie/issues/342>`_).
* Add ``PermissionType`` enum that details the type of permission being represented in any given response
  (values correspond to types detailed in documentation).
* Provide new ``permissions`` list in applicable API responses, with explicit ``name``, ``access``, ``scope`` and
  ``type`` fields for each ``PermissionSet`` represented as individual JSON object. Responses will also return the
  *explicit* string representations (see above) combined with the older *implicit* representation still returned
  in ``permission_names`` field for backward compatibility
  (note: ``DENY`` elements are only represented as *explicit* as there was no such *implicit* permissions before).
* Add more documentation details and examples about new permission concepts introduced.
* Add ``DELETE`` request views with ``permission`` object provided in body to allow deletion using ``PermissionSet``
  JSON representation instead of literal string by path variable.
  Still support ``permission_name`` path variable requests for backward compatibility for equivalent names.
* Add ``POST`` request support of ``permission`` JSON representation of ``PermissionSet`` provided in request body.
  Fallback to ``permission_name`` field for backward compatibility if equivalent ``permission`` is not found.
* Add new ``PUT`` request that updates a *possibly* existing ``permission`` (or create it if missing) without needing
  to execute any prior ``GET`` and/or ``DELETE`` requests that would normally be required to validate the existence or
  not of previously defined ``permission`` to avoid HTTP Conflict on ``POST``. This allows quicker changes of ``access``
  and ``scope`` modifiers applied on a given ``permission`` with a single operation
  (see details in issue `#342 <https://github.com/Ouranosinc/Magpie/issues/342>`_).
* Add many omitted tests regarding validation of operations on user/group service/resource permissions API routes.
* Add functional tests that evaluate ``MagpieAdapter`` behaviour and access control of service/resource from resolution
  of effective permissions upon incoming requests as they would be received by `Twitcher` proxy.
* Add ``Cache-Control: no-cache`` header support during ACL resolution of effective permissions on service/resource to
  ignore any caching optimization provided by ``beaker``.
* Add resource of type ``Process`` for ``ServiceWPS`` which can take advantage of new effective permission resolution
  method shared across service types to apply ``DescribeProcess`` and ``Execute`` permission on per-``Process`` basis
  (``match`` scope) or globally for all processes using permission on the parent WPS service (``recursive`` scope).
  (resolves `#266 <https://github.com/Ouranosinc/Magpie/issues/266>`_).
* Modify all implementations of ``Service`` to support effective permission resolution to natively support new
  permissions modifiers ``Access`` and ``Scope``.
* Adjust all API routes that provide ``effective`` query parameter to return resolved effective permissions of the
  ``User`` onto the targeted ``Resource``, and this for all applicable permissions on this ``Resource``, using new
  ``Access`` permission modifier.
* Adjust UI pages to provide selector of ``Access`` and ``Scope`` modifiers for all available permission names.
* Change UI permission pages to *Apply* batch edition of multiple entries simultaneously instead of one at the time.
* Improve rendering of UI disabled items such as inactive checkboxes or selectors when not applicable for given context.
* Refactor UI tree renderer to reuse same code for both ``User`` and ``Group`` resource permissions.
* Add UI button on ``User`` edit page to test its *effective permission* on a given resource.
  Must be in *inherited permissions* display mode to have access to test button, in order to help understand the result.

* | Upgrade migration script is added to convert existing implicit names to new explicit permission names.
  |
  | **WARNING**:
  | Downgrade migration drops any ``DENY`` permission that would be added in future versions,
    as they do not exist prior to this introduced version. The same applies for ``Process`` resources.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix incorrect regex employed for validation of service URL during registration.
* Replace HTTP status code ``400`` by ``403`` and ``422`` where applicable for invalid resource creation due to failing
  validations against reference parent service (relates to `#359 <https://github.com/Ouranosinc/Magpie/issues/359>`_).
* Fix UI rendering of ``Push to Phoenix`` notification when viewing service page with type ``WPS``.
* Fix UI rendering of some incorrect title background color for alert notifications.
* Fix UI rendering of tree view items with collapsible/expandable resource nodes.

`2.0.1 <https://github.com/Ouranosinc/Magpie/tree/2.0.1>`_ (2020-09-30)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* N/A

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``users`` typo in example ``config/config.yml`` (fixes `#354 <https://github.com/Ouranosinc/Magpie/issues/354>`_).
* Fix CLI operation ``batch_update_users`` to employ provided ``password`` from input file ``config/config.yml``
  instead of overriding it by random value. Omitted information will still auto-generate a random user password.
  (fixes `#355 <https://github.com/Ouranosinc/Magpie/issues/355>`_).

`2.0.0 <https://github.com/Ouranosinc/Magpie/tree/2.0.0>`_ (2020-07-31)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``/ui`` route redirect to frontpage when UI is enabled.
* Add ``/json`` route information into generated Swagger API documentation.
* Add tag description into generated Swagger API documentation.
* Add more usage details to start `Magpie` web application in documentation.
* Add database migration for new ``discoverable`` column of groups.
* Allow logged user to update its own information both via API and UI
  (relates to `#170 <https://github.com/Ouranosinc/Magpie/issues/170>`_).
* Allow logged user of any access-level to register by itself to ``discoverable`` groups.
* Change some UI CSS for certain pages to improve table readability.
* Add UI page to render error details from API responses (instead of default server-side HTML error rendering).
* Add ``MAGPIE_UI_THEME`` with new default *blue* theme and legacy *green* theme (with few improvements).
* Add more validation and inputs parameters to update ``Group`` information.
* Add UI input fields to allow administrator to update group description and group discoverability.
* Allow combined configuration files (``providers``, ``permissions``, ``users`` and ``groups`` sections) with
  resolution of inter-references between them. File can be specified with ``MAGPIE_CONFIG_PATH`` environment variable
  or ``magpie.config_path`` setting (example in ``configs``).
* Add configurable ``User`` creation parameters upon `Magpie` application startup through configuration files
  (fixes `#47 <https://github.com/Ouranosinc/Magpie/issues/47>`_ and
  `#204 <https://github.com/Ouranosinc/Magpie/issues/204>`_).
* Add disabled checkboxes for UI rendering of non-editable items to avoid user doing operations that will always be
  blocked by corresponding API validation (relates to `#164 <https://github.com/Ouranosinc/Magpie/issues/164>`_).
* Add more tests to validate forbidden operations such as update or delete of reserved ``User`` and ``Group`` details.
* Add active version tag at bottom of UI pages (same version as returned by API ``/version`` route).
* Enforce configuration parameters ``MAGPIE_SECRET``, ``MAGPIE_ADMIN_USER`` and ``MAGPIE_ADMIN_PASSWORD`` by explicitly
  defined values (either by environment variable or INI settings) to avoid using defaults for security purposes.
* Change CLI helper ``create_users`` to ``batch_update_users`` to better represent provided functionalities.
* Change CLI helper ``register_default_users`` to ``register_defaults`` to avoid confusion on groups also created.
* Extend CLI ``batch_update_users`` functionality with additional options and corresponding tests.
* Move all CLI helpers under ``magpie.cli`` and provide more details about them in documentation.
* Allow unspecified ``group_name`` during user creation request to employ ``MAGPIE_ANONYMOUS_GROUP`` by default
  (i.e.: created user will have no other apparent group membership since it is always attributed for public access).
* Change all ``PUT`` requests to ``PATCH`` to better reflect their actual behaviour according to RESTful best practices
  (partial field updates instead of complete resource replacement and conflict responses on duplicate identifiers).
* Add support of ``Accept`` header and ``format`` query parameter for all API responses, for content-types variations
  in either plain text, HTML, XML or JSON (default), and include applicable values in schemas for Swagger generation.
* Add support of new response content-type as XML (must request using ``Accept`` header or ``format`` query parameter).
* Add documentation details about different types of ``Permission``, interaction between various `Magpie` models,
  glossary and other general improvements (relates to `#332 <https://github.com/Ouranosinc/Magpie/issues/332>`_ and
  `#341 <https://github.com/Ouranosinc/Magpie/issues/341>`_).
* Add alternative response format for service and service-type paths using ``flatten`` query parameter to obtain a flat
  list of services instead of nested dictionaries (fixes `#345 <https://github.com/Ouranosinc/Magpie/issues/345>`_).
* Change pre-existing ``list`` query parameter of user-scoped views to ``flatten`` response format to match new query
  of service-scoped views.
* Add ``filtered`` query parameter for user-scoped resources permission listing when request user is an administrator.
* Obsolete all API routes using ``inherited_permission`` format (deprecated since ``0.7.4``) in favor of equivalent
  ``permissions?inherited=true`` query parameter modifier.
* Replace ``inherit`` query parameter wherever applicable by ``inherited`` to match documentation names, but preserve
  backward compatibility support of old name.
* Add ``MAGPIE_PASSWORD_MIN_LENGTH`` setting with corresponding validation of field during ``User`` creation and update.
* Avoid returning ``Service`` entries where user, group or both (according to request path and query options) does not
  actually have any permission set either directly on them or onto one of their respective children ``Resource``. This
  avoids unnecessarily exposing all ``Service`` for which the user cannot (or should not) be interacting with anyway.
* Add ``TWITCHER_HOST`` as alternative configuration parameter to define the service public URL, to have a similar
  naming convention as other use cases covered by ``MAGPIE_HOST`` and ``PHOENIX_HOST``.
* Modify ``PHOENIX_PUSH`` to be *disabled* by default to be consistent across all locations where corresponding
  feature is referenced (startup registration, CLI utility, API requests and UI checkbox option) and because this
  option is an advanced extension not to be considered as default behavior.
* Python 2.7 and Python 3.5 marked for deprecation (they remain in CI, but are not required to pass), as both
  reached their EOL as of January/September 2020.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix invalid API documentation of request body for ``POST /users/{user_name}/groups``.
* Fix `#164 <https://github.com/Ouranosinc/Magpie/issues/164>`_ (forbid *special* users and groups update and delete).
* Fix `#84 <https://github.com/Ouranosinc/Magpie/issues/84>`_ and
  `#171 <https://github.com/Ouranosinc/Magpie/issues/171>`_ with additional input validation.
* Fix `#194 <https://github.com/Ouranosinc/Magpie/issues/194>`_ to render API error responses according to content-type.
* Fix `#337 <https://github.com/Ouranosinc/Magpie/issues/337>`_ documentation mismatch with previously denied request
  users since they are now allowed to run these requests with new user-scoped functionalities
  (`#340 <https://github.com/Ouranosinc/Magpie/issues/340>`_).
* Fix bug introduced in `0.9.4 <https://github.com/Ouranosinc/Magpie/tree/0.9.4>`_
  (`4a23a49 <https://github.com/Ouranosinc/Magpie/commit/4a23a497e3ce1dc39ccaf31ba1857fc199d399db>`_) where some
  API routes would not return the `Allowed Permissions` for children ``Resource`` under ``Service``
  (only ``Service`` permissions would be filled), or when requesting ``Resource`` details directly.
* Fix input check to avoid situations where updating ``Resource`` name could cause involuntary duplicate errors.
* Fix minor HTML issues in mako templates.
* Fix invalid generation of default ``postgres.env`` file from ``magpie.env.example``.
  File ``postgres.env.example`` will now be correctly employed as documented.
* Make environment variable ``PHOENIX_PUSH`` refer to ``phoenix.push`` instead of ``magpie.phoenix_push`` to employ
  same naming schema as all other variables.

`1.11.0 <https://github.com/Ouranosinc/Magpie/tree/1.11.0>`_ (2020-06-19)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update this changelog to provide direct URL references to issues and tags from both `GitHub` and `Readthedocs`.
* Add generic ``magpie_helper`` CLI and prefix others using ``magpie_`` to help finding them in environment.
* Add minimal tests for CLI helpers to validate they can be found and called as intended
  (`#74 <https://github.com/Ouranosinc/Magpie/issues/74>`_).
* Add ``CLI`` tag for running specific tests related to helpers.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Remove some files from built docker image that shouldn't be there with more explicit ``COPY`` operations.
* Fix ``Dockerfile`` dependency of ``python3-dev`` causing build to fail.

`1.10.2 <https://github.com/Ouranosinc/Magpie/tree/1.10.2>`_ (2020-04-21)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add more documentation detail and references to existing `Magpie` utilities.
* Add ``readthedocs`` API page auto-generated from latest schemas extracted from source (redoc rendering of OpenAPI).
* Combine and update requirements for various python versions. Update setup parsing to support ``python_version``.
* Slack some requirements to obtain patches and bug fixes. Limit only when needed.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix issue related to ``sphinx-autoapi`` dependency (`#251 <https://github.com/Ouranosinc/Magpie/issues/251>`_).
* Fix reference link problems for generated documentation.

`1.10.1 <https://github.com/Ouranosinc/Magpie/tree/1.10.1>`_ (2020-04-02)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix failing generation of children resource tree when calling routes ``/resources/{id}`` due to literal ``Resource``
  class being used instead of the string representation. This also fixes UI Edit menu of a ``Service`` that add more
  at least one child ``Resource``.

`1.10.0 <https://github.com/Ouranosinc/Magpie/tree/1.10.0>`_ (2020-03-18)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* | When using logging level ``DEBUG``, `Magpie` requests will log additional details.
  |
  | **WARNING**:
  | Log entries with ``DEBUG`` level will potentially also include sensible information such as authentication cookies.
  | This level **SHOULD NOT** be used in production environments.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Adjust mismatching log levels across `Magpie` packages in case ``MAGPIE_LOG_LEVEL`` and corresponding
  ``magpie.log_level`` setting or ``logger_magpie`` configuration section were defined simultaneously.
  The values are back-propagated to ``magpie.constants`` for matching values and prioritize the `INI` file definitions.

`1.9.5 <https://github.com/Ouranosinc/Magpie/tree/1.9.5>`_ (2020-03-11)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix handling of ``Accept`` header introduced in PR `#259 <https://github.com/Ouranosinc/Magpie/issues/259>`_
  (i.e.: ``1.9.3`` and ``1.9.4``) specifically in the situation where a resource has the value ``magpie`` within
  its name (e.g.: such as the logo ``magpie.png``).

`1.9.4 <https://github.com/Ouranosinc/Magpie/tree/1.9.4>`_ (2020-03-10)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Add further handling of ``Accept`` header introduced in PR
  `#259 <https://github.com/Ouranosinc/Magpie/issues/259>`_ (ie: ``1.9.3``) as more use cases where not handled.

`1.9.3 <https://github.com/Ouranosinc/Magpie/tree/1.9.3>`_ (2020-03-10)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Add handling of ``Accept`` header to allow additional content-type when requesting UI related routes while
  `Magpie` application is being served under a route with additional prefix.
* Fix requirements dependency issue related to ``zope.interface`` and ``setuptools`` version mismatch.

`1.9.2 <https://github.com/Ouranosinc/Magpie/tree/1.9.2>`_ (2020-03-09)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Remove ``MAGPIE_ALEMBIC_INI_FILE_PATH`` configuration parameter in favor of ``MAGPIE_INI_FILE_PATH``.
* Forward ``.ini`` file provided as argument to ``MAGPIE_INI_FILE_PATH`` (e.g.: when using ``gunicorn --paste <ini>``).
* Load configuration file (previously only ``.cfg``) also using ``.yml``, ``.yaml`` and ``.json`` extensions.
* Add argument parameter for ``run_db_migration`` helper to specify the configuration ``ini`` file to employ.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Use forwarded input argument to ``MAGPIE_INI_FILE_PATH`` to execute database migration.
* Handle trailing ``/`` of HTTP path that would fail an ACL lookup of the corresponding service or resource.

`1.9.1 <https://github.com/Ouranosinc/Magpie/tree/1.9.1>`_ (2020-02-20)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update adapter docker image reference to ``birdhouse/twitcher:v0.5.3``.

`1.9.0 <https://github.com/Ouranosinc/Magpie/tree/1.9.0>`_ (2020-01-29)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Change database user name setting to lookup for ``MAGPIE_POSTGRES_USERNAME`` (and corresponding INI file setting)
  instead of previously employed ``MAGPIE_POSTGRES_USER``, but leave backward support if old parameter if not resolved
  by the new one.
* Add support of variables not prefixed by ``MAGPIE_`` for ``postgres`` database connection parameters, as well as
  all their corresponding ``postgres.<param>`` definitions in the INI file.

`1.8.0 <https://github.com/Ouranosinc/Magpie/tree/1.8.0>`_ (2020-01-10)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``MAGPIE_DB_URL`` configuration parameter to define a database connection with full URL instead of individual
  parts (notably ``MAGPIE_POSTGRES_<>`` variables).
* Add ``bandit`` security code analysis and apply some detected issues
  (`#168 <https://github.com/Ouranosinc/Magpie/issues/168>`_).
* Add more code linting checks using various test tools.
* Add smoke test of built docker image to `Travis-CI` pipeline.
* Bump ``alembic>=1.3.0`` to remove old warnings and receive recent fixes.
* Move ``magpie.utils.SingletonMeta`` functionality from adapter to reuse it in ``null`` test checks.
* Rename ``resource_tree_service`` and ``remote_resource_tree_service`` to their uppercase equivalents.
* Removed module ``magpie.definitions`` in favor of directly importing appropriate references as needed.
* Improve ``make help`` targets descriptions.
* Change to Apache license.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix incorrectly installed ``authomatic`` library following update of reference branch
  (https://github.com/fmigneault/authomatic/tree/httplib-port) with ``master`` branch merged update
  (https://github.com/authomatic/authomatic/pull/195/commits/d7897c5c4c20486b55cb2c70724fa390c9aa7de6).
* Fix documentation links incorrectly generated for `readthedocs` pages.
* Fix missing or incomplete configuration documentation details.
* Fix many linting issues detected by integrated tools.

`1.7.4 <https://github.com/Ouranosinc/Magpie/tree/1.7.4>`_ (2019-12-03)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~

* Add sorting by name of configuration files (permissions/providers) when loaded from a containing directory path.
* Add `readthedocs` references to README.

`1.7.3 <https://github.com/Ouranosinc/Magpie/tree/1.7.3>`_ (2019-11-20)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix 500 error when getting user's services on ``/users/{user_name}/services``.

`1.7.2 <https://github.com/Ouranosinc/Magpie/tree/1.7.2>`_ (2019-11-15)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``gunicorn>=20.0.0`` breaking change not compatible with alpine: pin ``gunicorn==19.9.0``.

`1.7.1 <https://github.com/Ouranosinc/Magpie/tree/1.7.1>`_ (2019-11-12)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix resource sync process and update cron job running it
  (`#226 <https://github.com/Ouranosinc/Magpie/issues/226>`_).
* Fix configuration files not loaded from directory by application due to more restrictive file check.
* Fix a test validating applicable user resources and permissions that could fail if `anonymous` permissions where
  generated into the referenced database connection (eg: from loading a ``permissions.cfg`` or manually created ones).

`1.7.0 <https://github.com/Ouranosinc/Magpie/tree/1.7.0>`_ (2019-11-04)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``docs/configuration.rst`` file that details all configuration settings that are employed by ``Magpie``
  (`#180 <https://github.com/Ouranosinc/Magpie/issues/180>`_).
* Add more details about basic usage of `Magpie` in ``docs/usage.rst``.
* Add details about external provider setup in ``docs/configuration``
  (`#173 <https://github.com/Ouranosinc/Magpie/issues/173>`_).
* Add specific exception classes for ``register`` sub-package operations.
* Add ``PHOENIX_HOST`` variable to override default ``HOSTNAME`` as needed.
* Add support of ``MAGPIE_PROVIDERS_CONFIG_PATH`` and ``MAGPIE_PERMISSIONS_CONFIG_PATH`` pointing to a directory to
  load multiple similar configuration files contained in it.
* Add environment variable expansion support for all fields within ``providers.cfg`` and ``permissions.cfg`` files.

`1.6.3 <https://github.com/Ouranosinc/Magpie/tree/1.6.3>`_ (2019-10-31)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix the alembic database version number in the /version route
  (`#165 <https://github.com/Ouranosinc/Magpie/issues/165>`_).
* Fix failing migration step due to missing ``root_service_id`` column in database at that time and version.

`1.6.2 <https://github.com/Ouranosinc/Magpie/tree/1.6.2>`_ (2019-10-04)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix a bug in ``ows_parser_factory`` that caused query parameters for wps services to be case sensitive.

`1.6.1 <https://github.com/Ouranosinc/Magpie/tree/1.6.1>`_ (2019-10-01)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix migration script for ``project-api`` service type.

`1.6.0 <https://github.com/Ouranosinc/Magpie/tree/1.6.0>`_ (2019-09-20)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add an utility script ``create_users`` for quickly creating multiple users from a list of email addresses
  (`#219 <https://github.com/Ouranosinc/Magpie/issues/219>`_).
* Add PEP8 auto-fix make target ``lint-fix`` that will correct any PEP8 and docstring problem to expected format.
* Add auto-doc of make target ``help`` message.
* Add ACL caching option and documentation (`#218 <https://github.com/Ouranosinc/Magpie/issues/218>`_).

`1.5.0 <https://github.com/Ouranosinc/Magpie/tree/1.5.0>`_ (2019-09-09)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Use singleton interface for ``MagpieAdapter`` and ``MagpieServiceStore`` to avoid class recreation and reduce request
  time by `Twitcher` when checking for a service by name.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix issue of form submission not behaving as expected when pressing ``<ENTER>`` key
  (`#209 <https://github.com/Ouranosinc/Magpie/issues/209>`_).
* Fix 500 error when deleting a service resource from UI (`#195 <https://github.com/Ouranosinc/Magpie/issues/195>`_).

`1.4.0 <https://github.com/Ouranosinc/Magpie/tree/1.4.0>`_ (2019-08-28)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Apply ``MAGPIE_ANONYMOUS_GROUP`` to every new user to ensure they can access public resources when they are logged in
  and that they don't have the same resource permission explicitly set for them.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix migration script hastily removing anonymous group permissions without handling and transferring them accordingly.
* Use settings during default user creation instead of relying only on environment variables, to reflect runtime usage.

`1.3.4 <https://github.com/Ouranosinc/Magpie/tree/1.3.4>`_ (2019-08-09)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix migration script errors due to incorrect object fetching from db
  (`#149 <https://github.com/Ouranosinc/PAVICS/pull/149>`_).

`1.3.3 <https://github.com/Ouranosinc/Magpie/tree/1.3.3>`_ (2019-07-11)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update ``MagpieAdapter`` to use `Twitcher` version ``0.5.2`` to employ HTTP status code fixes and additional
  API route details :
  - https://github.com/bird-house/twitcher/pull/79
  - https://github.com/bird-house/twitcher/pull/84

`1.3.2 <https://github.com/Ouranosinc/Magpie/tree/1.3.2>`_ (2019-07-09)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``use_tweens=True`` to ``request.invoke_subrequest`` calls in order to properly handle the nested database
  transaction states with the manager (`#203 <https://github.com/Ouranosinc/Magpie/issues/203>`_).
  Automatically provides ``pool_threadlocal`` functionality added in ``1.3.1`` as per implementation of
  ``pyramid_tm`` (`#201 <https://github.com/Ouranosinc/Magpie/issues/201>`_).

`1.3.1 <https://github.com/Ouranosinc/Magpie/tree/1.3.1>`_ (2019-07-05)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``pool_threadlocal=True`` setting for database session creation to allow further connections across workers
  (see `#201 <https://github.com/Ouranosinc/Magpie/issues/201>`_,
  `#202 <https://github.com/Ouranosinc/Magpie/issues/202>`_ for further information).

`1.3.0 <https://github.com/Ouranosinc/Magpie/tree/1.3.0>`_ (2019-07-02)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Move ``get_user`` function used specifically for `Twitcher` via ``MagpieAdapter`` where it is employed.
* Remove obsolete, unused and less secure code that converted a token to a matching user by ID.
* Avoid overriding a logger level specified by configuration by checking for ``NOTSET`` beforehand.
* Add debug logging of Authentication Policy employed within ``MagpieAdapter``.
* Add debug logging of Authentication Policy at config time for both `Twitcher` and `Magpie`.
* Add debug logging of Cookie identification within ``MagpieAdapter``.
* Add route ``/verify`` with ``POST`` request to verify matching Authentication Policy tokens retrieved between
  `Magpie` and `Twitcher` (via ``MagpieAdapter``).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``MagpieAdapter`` name incorrectly called when displayed using route ``/info`` from `Twitcher`.

`1.2.1 <https://github.com/Ouranosinc/Magpie/tree/1.2.1>`_ (2019-06-28)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Log every permission requests.

`1.2.0 <https://github.com/Ouranosinc/Magpie/tree/1.2.0>`_ (2019-06-27)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Provide some documentation about ``magpie.constants`` module behaviour.
* Remove some inspection comments by using combined requirements files.
* Add constant ``MAGPIE_LOG_PRINT`` (default: ``False``) to enforce printing logs to console
  (equivalent to specifying a ``sys.stdout/stderr StreamHandler`` in ``magpie.ini``, but is not enforced anymore).
* Update logging config to avoid duplicate outputs and adjust code to respect specified config.
* Add some typing for ACL methods.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``Permission`` enum vs literal string usage during ACL resolution for some services and return enums when calling.
  ``ServiceInterface.permission_requested`` method.
* Fix user/group permission checkboxes not immediately reflected in UI after clicking them
  (`#160 <https://github.com/Ouranosinc/Magpie/issues/160>`_).

`1.1.0 <https://github.com/Ouranosinc/Magpie/tree/1.1.0>`_ (2019-05-28)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Prioritize settings (ie: ``magpie.ini`` values) before environment variables and ``magpie.constants`` globals.
* Allow specifying ``magpie.scheme`` setting to generate the ``magpie.url`` with it if the later was omitted.
* Look in settings for required parameters for function ``get_admin_cookies``.
* Use API definitions instead of literal strings for routes employed in ``MagpieAdapter``.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix erroneous ``Content-Type`` header retrieved from form submission getting forwarded to API requests.
* Fix user name update failing because of incomplete db transaction.

`1.0.0 <https://github.com/Ouranosinc/Magpie/tree/1.0.0>`_ (2019-05-24)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``Dockerfile.adapter`` to build and configure ``MagpieAdapter`` on top of ``Twitcher >= 0.5.0``.
* Add auto-bump of history version.
* Update history with more specific sections.
* Improve ``Makefile`` targets with more checks and re-using variables.
* Add constant alternative search of variant ``magpie.[variable_name]`` for ``MAGPIE_[VARIABLE_NAME]``.
* Add tests for ``get_constant`` function.
* Regroup all configurations in a common file located in ``config/magpie.ini``.
* Remove all other configuration files (``tox.ini``, ``alembic.ini``, ``logging.ini``).
* Drop `Makefile` target ``test-tox``.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Use an already created configurator when calling ``MagpieAdapter.configurator_factory``
  instead of recreating it from settings to preserve potential previous setup and includes.
* Use default ``WPSGet``/``WPSPost`` for ``magpie.owsrequest.OWSParser`` when no ``Content-Type`` header is specified
  (``JSONParser`` was used by default since missing ``Content-Type`` was resolved to ``application/json``, which
  resulted in incorrect parsing of `WPS` requests parameters).
* Actually fetch required `JSON` parameter from the request body if ``Content-Type`` is ``application/json``.
* Convert ``Permission`` enum to string for proper ACL comparison in ``MagpieOWSSecurity``.
* Fix ``raise_log`` function to allow proper evaluation against ``Exception`` type instead of ``message`` property.

`0.10.0 <https://github.com/Ouranosinc/Magpie/tree/0.10.0>`_ (2019-04-15)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Refactoring of literal strings to corresponding ``Permission`` enum
  (`#167 <https://github.com/Ouranosinc/Magpie/issues/167>`_).
* Change all incorrect usages of HTTP ``Not Acceptable [406]`` to ``Bad Request [400]``
  (`#163 <https://github.com/Ouranosinc/Magpie/issues/163>`_).
* Add ``Accept`` header type checking before requests and return HTTP ``Not Acceptable [406]`` if invalid.
* Code formatting changes for consistency and cleanup of redundant/misguiding names
  (`#162 <https://github.com/Ouranosinc/Magpie/issues/162>`_).
* Add option ``MAGPIE_UI_ENABLED`` allowing to completely disable all ``/ui`` route (enabled by default).
* Add more unittests (`#74 <https://github.com/Ouranosinc/Magpie/issues/74>`_).

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix swagger responses status code and description and fix erroneous body
  (`#126 <https://github.com/Ouranosinc/Magpie/issues/126>`_).
* Fix invalid member count value returned on ``/groups/{id}`` request.
* Fix invalid ``DELETE /users/{usr}/services/{svc}/permissions/{perm}`` request not working.

`0.9.6 <https://github.com/Ouranosinc/Magpie/tree/0.9.6>`_ (2019-03-28)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update `Travis-CI` test suite execution by enabling directly running PEP8 lint checks.
* Change some `PyCharm` specific inspection comment in favor of IDE independent ``noqa`` equivalents.

`0.9.5 <https://github.com/Ouranosinc/Magpie/tree/0.9.5>`_ (2019-02-28)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Logging requests and exceptions according to `MAGPIE_LOG_REQUEST` and `MAGPIE_LOG_EXCEPTION` values.
* Better handling of HTTP ``Unauthorized [401]`` and ``Forbidden [403]`` according to unauthorized view
  (invalid access token/headers or forbidden operation under view).
* Better handling of HTTP ``Not Found [404]`` and ``Method Not Allowed [405]`` on invalid routes and request methods.
* Adjust ``Dockerfile`` copy order to save time if requirements did not change.

`0.9.4 <https://github.com/Ouranosinc/Magpie/tree/0.9.4>`_ (2019-02-19)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Address YAML security issue using updated package distribution.
* Improve permission warning details in case of error when parsing.
* Add multiple tests for item registration via API.
* Minor changes to some variable naming to respect convention across the source code.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Use sub-transaction when running service update as a session can already be in effect with a transaction due to
  previous steps employed to fetch service details and/or UI display.

`0.9.3 <https://github.com/Ouranosinc/Magpie/tree/0.9.3>`_ (2019-02-18)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Greatly reduce docker image size using ``Alpine`` base and redefining its creation steps.
* Use ``get_constant`` function to allow better retrieval of database related configuration from all setting variations.
* Simplify database creation using ``sqlalchemy_utils``.

`0.9.2 <https://github.com/Ouranosinc/Magpie/tree/0.9.2>`_ (2019-02-15)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Allow quick functional testing using sequences of local app form submissions.
* Add test methods for UI redirects to other views from button click in displayed page.
* Change resource response for generic ``resource: {<info>}`` instead of ``{resource-id}: {<info>}``.
* Add more typing hints of headers and cookies parameters to functions.
* Improve handling of invalid request input parameter causing parsing errors using ``error_badrequest`` decorator.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix UI add child button broken by introduced ``int`` resource id type checking.

`0.9.1 <https://github.com/Ouranosinc/Magpie/tree/0.9.1>`_ (2019-02-14)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Reduce docker image build time by skipping irrelevant files causing long context loading using ``.dockerignore``.
* Use sub-requests API call for UI operations (fixes issue `#114 <https://github.com/Ouranosinc/Magpie/issues/114>`_).
* Add new route ``/services/types`` to obtain a list of available service types.
* Add ``resource_child_allowed`` and ``resource_types_allowed`` fields in service response.
* Change service response for generic ``service: {<info>}`` instead of ``{service-name}: {<info>}``.
* Add new route ``/services/types/{svc_type}/resources`` for details about child service type resources.
* Add error handling of reserved route keywords service ``types`` for ``/services/{svc}`` routes and current user
  defined by ``MAGPIE_LOGGED_USER`` for ``/users/{usr}`` routes.
* Additional tests for new routes and operations previously left unevaluated.

`0.9.0 <https://github.com/Ouranosinc/Magpie/tree/0.9.0>`_ (2019-02-01)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add permissions config to auto-generate user/group rules on startup.
* Attempt db creation on first migration if not existing.
* Add continuous integration testing and deployment (with python 2/3 tests).
* Ensure python compatibility for Python 2.7, 3.5, 3.6 (via `Travis-CI`).
* Reduce excessive ``sqlalchemy`` logging using ``MAGPIE_LOG_LEVEL >= INFO``.
* Use schema API route definitions for UI calls.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix invalid conflict service name check on service update request.
* Fix many invalid or erroneous swagger specifications.

`0.8.2 <https://github.com/Ouranosinc/Magpie/tree/0.8.2>`_ (2019-01-21)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Provide user ID on API routes returning user info.

`0.8.1 <https://github.com/Ouranosinc/Magpie/tree/0.8.1>`_ (2018-12-20)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update ``MagpieAdapter`` to match process store changes.

`0.8.0 <https://github.com/Ouranosinc/Magpie/tree/0.8.0>`_ (2018-12-18)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Adjust typing of ``MagpieAdapter``.
* Reuse `store` objects in ``MagpieAdapter`` to avoid recreation on each request.
* Add ``HTTPNotImplemented [501]`` error in case of incorrect adapter configuration.

`0.7.12 <https://github.com/Ouranosinc/Magpie/tree/0.7.12>`_ (2018-12-06)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add flag to return `effective` permissions from user resource permissions requests.

`0.7.11 <https://github.com/Ouranosinc/Magpie/tree/0.7.11>`_ (2018-12-03)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Allow more processes to be returned by an administrator user when parsing items in ``MagpieAdapter.MagpieProcess``.

`0.7.10 <https://github.com/Ouranosinc/Magpie/tree/0.7.10>`_ (2018-11-30)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Updates to ``MagpieAdapter.MagpieProcess`` according to process visibility.

`0.7.9 <https://github.com/Ouranosinc/Magpie/tree/0.7.9>`_ (2018-11-20)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``isTrue`` and ``isFalse`` options to ``api_except.verify_param`` utility function.
* Add better detail and error code for login failure instead of generic failure.
* Use ``UserService`` for some user operations that were still using the old method.
* Add multiple tests for ``/users/[...]`` related routes.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fixes to JSON body to be returned by some ``MagpieAdapter.MagpieProcess`` operations.

`0.7.8 <https://github.com/Ouranosinc/Magpie/tree/0.7.8>`_ (2018-11-16)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Hide service private URL on non administrator level requests.
* Make cookies expire-able by setting ``MAGPIE_COOKIE_EXPIRE`` and provide cookie only on http
  (`JS CSRF` attack protection).
* Update ``MagpieAdapter.MagpieOWSSecurity`` for `WSO2` seamless integration with Authentication header token.
* Update ``MagpieAdapter.MagpieProcess`` for automatic handling of REST-API WPS process route access permissions.
* Update ``MagpieAdapter.MagpieService`` accordingly to inherited resources and service URL changes.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fixes related to postgres DB entry conflicting inserts and validations.

`0.7.7 <https://github.com/Ouranosinc/Magpie/tree/0.7.7>`_ (2018-11-06)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add error handing during user permission creation in ``MagpieAdapter.MagpieProcess``.

0.7.6 (n/a)
------------------------------------------------------------------------------------

* Invalid version skipped due to generation error.

`0.7.5 <https://github.com/Ouranosinc/Magpie/tree/0.7.5>`_ (2018-11-05)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix handling of resource type in case the resource ID refers to a ``service``.
* Pin ``pyramid_tm==2.2.1``.

`0.7.4 <https://github.com/Ouranosinc/Magpie/tree/0.7.4>`_ (2018-11-01)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add inherited resource permission with querystring (deprecate ``inherited_<>`` routes warnings).

`0.7.3 <https://github.com/Ouranosinc/Magpie/tree/0.7.3>`_ (2018-10-26)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Improve ``MagpieAdapter`` logging.
* Add ``MagpieAdapter`` initialization with parent object initialization and configuration.

`0.7.2 <https://github.com/Ouranosinc/Magpie/tree/0.7.2>`_ (2018-10-19)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``MagpieAdapter.MagpieOWSSecurity.update_request_cookies`` method that handles conversion of ``Authorization``
  header into the required authentication cookie employed by `Magpie` and `Twitcher` via integrated ``MagpieAdapter``.
* Add multiple cosmetic improvements to UI (images, styles, etc.).
* Improve login error reporting in UI.
* Improve reporting of invalid parameters on creation UI pages.
* Add better display of the logged user if any in the UI.
* Add more Swagger API documentation details for returned resources per HTTP status codes.
* Add external provider type ``WSO2`` and relevant setting variables to configure the referenced instance.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix external providers login support with ``authomatic`` using API/UI (validated for `DKRZ`, `GitHub` and `WSO2`).
* Fix login/logout button in UI.

`0.7.1 <https://github.com/Ouranosinc/Magpie/tree/0.7.1>`_ (2018-10-16)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Avoid displaying the private service URL when not permitted for the current user.
* Add more test and documentation updates.

`0.7.0 <https://github.com/Ouranosinc/Magpie/tree/0.7.0>`_ (2018-10-05)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add service resource auto-sync feature.
* Return user/group services if any sub-resource has permissions.

`0.6.5 <https://github.com/Ouranosinc/Magpie/tree/0.6.5>`_ (2018-09-13)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix ``MagpieAdapter`` setup using ``TWITCHER_PROTECTED_URL`` setting.
* Fix ``MagpieAdapter.MagpieService`` handling of returned list of services.
* Fix Swagger JSON path retrieval for some edge case configuration values.

`0.6.4 <https://github.com/Ouranosinc/Magpie/tree/0.6.4>`_ (2018-10-10)
------------------------------------------------------------------------------------

0.6.2 - 0.6.3 (n/a)
------------------------------------------------------------------------------------

* Invalid versions skipped due to generation error.

`0.6.1 <https://github.com/Ouranosinc/Magpie/tree/0.6.1>`_ (2018-06-29)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Update ``Makefile`` targets.
* Change how ``postgres`` configurations are retrieved using variables specific to `Magpie`.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Properly return values of field ``permission_names`` under ``/services/.*`` routes.

`0.6.0 <https://github.com/Ouranosinc/Magpie/tree/0.6.0>`_ (2018-06-26)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add ``/magpie/api/`` route to locally display the Magpie REST API documentation.
* Move many source files around to regroup by API/UI functionality.
* Auto-generation of swagger REST API documentation using ``cornice_swagger``.
* Add more unit tests.
* Validation of permitted resource types children under specific parent service or resource.
* ``ServiceAPI`` to filter ``read``/``write`` of specific HTTP methods on route parts.
* ``ServiceAccess`` to filter top-level route ``access`` permission of a generic service URL.

`0.5.4 <https://github.com/Ouranosinc/Magpie/tree/0.5.4>`_ (2018-06-08)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Improve some routes returned codes, inputs check, and requests formats (JSON).

`0.5.3 <https://github.com/Ouranosinc/Magpie/tree/0.5.3>`_ (2018-06-07)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add utility functions like ``get_multiformat_any`` to help retrieving contents regardless of
  request method and/or content-type.

`0.5.2 <https://github.com/Ouranosinc/Magpie/tree/0.5.2>`_ (2018-06-06)
------------------------------------------------------------------------------------

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix returned inherited group permissions of a user.
* Fix clearing of cookies when logout is accomplished.

`0.5.1 <https://github.com/Ouranosinc/Magpie/tree/0.5.1>`_ (2018-06-06)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Independent user/group permissions, no more 'personal' group to reflect user permissions.
* Service specific resources with service*-typed* Resource permissions.
* More verification of resources permissions under specific services.
* Reference to root service from each sub-resource.

`0.5.0 <https://github.com/Ouranosinc/Magpie/tree/0.5.0>`_ (2018-06-06)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Change defaults for ``ADMIN_GROUP`` and ``USER_GROUP`` variables.
* Major refactoring of ``Magpie`` application, both for API and UI.
* Split utilities and view functions into corresponding files for each type of item.
* Add more ``alembic`` database migration scripts steps for missing incremental versioning of schema and data.
* Inheritance of user and group permissions with different routes.

`0.4.5 <https://github.com/Ouranosinc/Magpie/tree/0.4.5>`_ (2018-05-14)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Handle login failure into different use cases in order to return appropriate HTTP status code and message.
* Add login error reporting with a banner in UI.

`0.4.4 <https://github.com/Ouranosinc/Magpie/tree/0.4.4>`_ (2018-05-11)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add UI view for user detail edition, including personal information and group membership.

`0.4.3 <https://github.com/Ouranosinc/Magpie/tree/0.4.3>`_ (2018-05-09)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Loosen ``psycopg2`` version requirement.

`0.4.2 <https://github.com/Ouranosinc/Magpie/tree/0.4.2>`_ (2018-05-09)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Loosen ``PyYAML`` version requirement.
* Update documentation details.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix installation error (`#27 <https://github.com/Ouranosinc/Magpie/issues/27>`_).

`0.4.1 <https://github.com/Ouranosinc/Magpie/tree/0.4.1>`_ (2018-05-08)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Improvement to UI element rendering with focus/hover/etc.
* Push to Phoenix adjustments and new push button option and alert/confirmation banner.

`0.4.0 <https://github.com/Ouranosinc/Magpie/tree/0.4.0>`_ (2018-03-23)
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Default admin permissions.
* Block UI view permissions of all pages if not logged in.

0.3.x
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add `ncWMS` support for `getmap`, `getcapabilities`, `getmetadata` on ``thredds`` resource.
* Add `ncWMS2` to default providers.
* Add `geoserverwms` service.
* Remove load balanced `Malleefowl` and `Catalog`.
* Push service provider updates to `Phoenix` on service edit or initial setup with `getcapabilities` for `anonymous`.
* Major update of `Magpie REST API 0.2.x documentation` to match returned codes/messages from 0.2.0 changes.
* Normalise additional HTTP request responses omitted from 0.2.0 (404, 500, and other missed responses).
* Remove internal api call, separate login external from local, direct access to `ziggurat` login.

Bug Fixes
~~~~~~~~~~~~~~~~~~~~~
* Fix UI ``"Magpie Administration"`` to redirect toward home page instead of `PAVICS` platform.
* Fix bug during user creation against preemptive checks.
* Fix issues from `0.2.x` versions.

0.2.0
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Revamp HTTP standard error output format, messages, values and general error/exception handling.
* Update `Magpie REST API 0.2.0 documentation`.

0.1.1
------------------------------------------------------------------------------------

Features / Changes
~~~~~~~~~~~~~~~~~~~~~
* Add edition of service URL via ``PUT /{service_name}``.

0.1.0
------------------------------------------------------------------------------------

* First structured release.
