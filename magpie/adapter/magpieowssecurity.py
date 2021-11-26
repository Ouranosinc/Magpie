import logging
from copy import copy
from distutils.version import LooseVersion
from typing import TYPE_CHECKING

import requests
from beaker.cache import cache_region, cache_regions
from pyramid.authentication import IAuthenticationPolicy
from pyramid.authorization import IAuthorizationPolicy
from pyramid.httpexceptions import HTTPBadRequest, HTTPForbidden, HTTPNotFound, HTTPOk, HTTPUnauthorized
from pyramid.settings import asbool
from requests.cookies import RequestsCookieJar
from simplejson import JSONDecodeError
from six.moves.urllib.parse import urlparse

from magpie.api.exception import evaluate_call, verify_param
from magpie.api.schemas import ProviderSigninAPI
from magpie.constants import get_constant
from magpie.db import get_connected_session
from magpie.models import Service
from magpie.permissions import Permission
from magpie.services import invalidate_service, service_factory
from magpie.utils import CONTENT_TYPE_JSON, get_authenticate_headers, get_logger, get_magpie_url, get_settings

# WARNING:
#   Twitcher available only when this module is imported from it.
#   It is installed during tests for evaluation.
#   Module 'magpie.adapter' should not be imported from 'magpie' package.
from twitcher.__version__ import __version__ as twitcher_version  # noqa
from twitcher.owsexceptions import OWSAccessForbidden  # noqa; noqa
from twitcher.owsexceptions import OWSException  # noqa
from twitcher.owsexceptions import OWSInvalidParameterValue  # noqa
from twitcher.owsexceptions import OWSMissingParameterValue  # noqa
from twitcher.utils import parse_service_name  # noqa

if LooseVersion(twitcher_version) >= LooseVersion("0.6.0"):
    from twitcher.interface import OWSSecurityInterface  # noqa  # pylint: disable=E0611  # Twitcher >= 0.6.x
else:
    from twitcher.owssecurity import OWSSecurityInterface  # noqa

LOGGER = get_logger("TWITCHER|{}".format(__name__))
if TYPE_CHECKING:
    from typing import Dict, Tuple

    from pyramid.request import Request

    from magpie.services import ServiceInterface
    from magpie.typedefs import AnyValue, Str


class MagpieOWSSecurity(OWSSecurityInterface):

    def __init__(self, request):
        super(MagpieOWSSecurity, self).__init__()
        self.settings = get_settings(request)
        self.request = request
        self.magpie_url = get_magpie_url(self.settings)
        self.twitcher_ssl_verify = asbool(self.settings.get("twitcher.ows_proxy_ssl_verify", True))
        self.twitcher_protected_path = self.settings.get("twitcher.ows_proxy_protected_path", "/ows")

    @cache_region("service")
    def _get_service_cached(self, service_name):
        # type: (Str) -> Tuple[ServiceInterface, Dict[str, AnyValue]]
        """
        Cache this method with :py:mod:`beaker` based on the provided caching key parameters.

        If the cache is not hit (expired timeout or new key entry), calls :func:`service_factory` to retrieve the
        actual :class:`ServiceInterface` implementation. Otherwise, returns the cached service to avoid SQL queries.

        .. note::
            Function arguments are required to generate caching keys by which cached elements will be retrieved.

        .. seealso::
            - :meth:`magpie.adapter.magpieowssecurity.MagpieOWSSecurity.get_service`
            - :meth:`magpie.adapter.magpieservice.MagpieServiceStore.fetch_by_name`
        """
        session = get_connected_session(self.request)
        service = evaluate_call(lambda: Service.by_service_name(service_name, db_session=session),
                                http_error=HTTPForbidden, msg_on_fail="Service query by name refused by db.")
        verify_param(service, not_none=True, param_name="service_name",
                     http_error=HTTPNotFound, msg_on_fail="Service name not found.")

        # return a specific type of service (eg: ServiceWPS with all the ACL loaded according to the service impl.)
        service_impl = service_factory(service, self.request)
        service_data = dict(service.get_appstruct())
        return service_impl, service_data

    def get_service(self, request):
        # type: (Request) -> ServiceInterface
        """
        Obtains the service referenced by the request.

        Caching is automatically handled according to configured application settings and whether the specific service
        name being requested was already processed recently and not expired.
        """

        # make sure the cache is invalidated to retrieve 'fresh' service from database if requested or cache disabled
        self.request = request
        service_name = parse_service_name(request.path, self.twitcher_protected_path)
        if "service" not in cache_regions:
            cache_regions["service"] = {"enabled": False}
        if self.request.headers.get("Cache-Control") == "no-cache":
            LOGGER.debug("Cache invalidation requested. Removing items from service region: [%s]", service_name)
            invalidate_service(service_name)

        # retrieve the implementation and the service data contained in the database entry
        LOGGER.debug("Retrieving service [%s]", service_name)
        service_impl, service_data = self._get_service_cached(service_name)

        # Because the database service *could* be linked to cached item, expired session creates unbound object
        # - rebuild the service from cached data such that following operations can retrieve details as needed
        #   (this avoids SQLAlchemy running lazy-loading of pre-fetched data, since it is readily available)
        # - reapply the request which contains the methods to retrieve database session and request user from it
        #   (this ensures that any other places using the request/db/user will use the current one instead of cached)
        if service_impl.request is not request:
            LOGGER.warning("Using cached service")
            service_cached = Service()
            service_cached.populate_obj(service_data)
            service_impl.service = service_cached
            service_impl.request = request
            service_impl.request.db = get_connected_session(request)

        # Create a shallow copy of the service implementation to mitigate session handling by distinct requests.
        # - Because multiple threads/workers can retrieve the (same) cached definition from memory during concurrent
        #   requests, any modification to underlying session object references (session state in 'service_impl.service'
        #   and session reference in 'service_impl.request.db') could modify them across parallel worker operations.
        #   Returning the same cached object can cause a request fully cached (service+acl) that finishes quickly to
        #   close a connection or transaction while another only partially cached (service only, acl to compute) still
        #   uses it and expects it to be open, causing unexpected lost of session/transaction midway.
        # - See also scoped-session employed in 'get_session_factory' that should generate different thread-local
        #   sessions to try minimizing this from happening across concurrent requests (default session not thread safe).
        #   (https://docs.sqlalchemy.org/en/13/orm/contextual.html#contextual-thread-local-sessions)
        service_impl = copy(service_impl)
        return service_impl

    def verify_request(self, request):
        # type: (Request) -> bool
        """
        Verify that the service request is allowed.

        .. versionadded:: 3.18
            Available only in ``Twitcher >= 0.6.x``.
        """
        try:
            self.check_request(request)
            return True
        except OWSException:
            return False
        except Exception as exc:
            LOGGER.error("Unhandled exception. Derived OWSException is expected for unauthorized access.", exc_info=exc)
            return False

    def check_request(self, request):
        # type: (Request) -> None
        """
        Verifies if the request user has access to the targeted resource according to parent service and permissions.

        If the request path corresponds to configured `Twitcher` proxy, evaluate the :term:`ACL`.
        Otherwise, ignore request access validation.

        In the case `Twitcher` proxy path is matched, the :term:`Logged User` **MUST** be allowed access following
        :term:`Effective Permissions` resolution via :term:`ACL`.
        Otherwise, :exception:`OWSAccessForbidden` is raised.

        Failing to parse the request or any underlying component that raises an exception will be left up to the
        parent caller to handle the exception. In most typical use case, this means `Twitcher` will raise a
        generic :exception:`OWSException` with ``NoApplicableCode``, unless the exception was more specifically handled.

        :raises OWSAccessForbidden:
            If the user does not have access to the targeted resource under the service.
        :raises HTTPBadRequest:
            If a request parsing error was detected when trying to resolve the permission based on the service/resource.
        :raises Exception:
            Any derived exception that was not explicitly handled is re-raised directly after logging the event.
        :returns: Nothing if user has access.
        """
        if request.path.startswith(self.twitcher_protected_path):
            # each service implementation defines their ACL and permission resolution using request definition
            service_impl = self.get_service(request)
            LOGGER.debug("Using service: [%s]", service_impl)

            perm_exc = None
            try:
                LOGGER.debug("Resolving requested permission based on parsing implementation of service...")
                # parse request (GET/POST) to get the permission requested for that service
                permission_requested = service_impl.permission_requested()
                # convert permission enum to str for comparison
                permission_requested = Permission.get(permission_requested).value if permission_requested else None
            except HTTPBadRequest as exc:
                LOGGER.debug("Error raised when parsing requested permission based request and service implementation.")
                perm_exc = exc
                # if special case of HTTPBadRequest was raised, attempt providing a better description of the error
                # otherwise, Twitcher will capture other exceptions and re-raise them as generic OWSException
                try:
                    data = getattr(exc, "json", {})
                except JSONDecodeError:
                    data = {}
                detail = data.pop("detail", None) or str(exc)
                ows_err = OWSMissingParameterValue if data.get("value", None) is None else OWSInvalidParameterValue
                locator = data.get("param", {}).get("name", None)
                raise ows_err(detail, value=locator)
            except Exception as exc:
                perm_exc = exc
                raise  # re-raise and let Twitcher handle it, only do this to obtain 'exc' for logging
            finally:
                if perm_exc is not None:
                    LOGGER.debug("Error during service [%s] permission requested resolution [%s](%s)",
                                 service_impl.service.resource_name, type(perm_exc).__name__, perm_exc)

            if permission_requested:
                LOGGER.info("User %s is requesting '%s' permission on [%s]",
                            request.user, permission_requested, request.path)
                self.update_request_cookies(request)
                authn_policy = request.registry.queryUtility(IAuthenticationPolicy)  # noqa
                authz_policy = request.registry.queryUtility(IAuthorizationPolicy)   # noqa
                principals = authn_policy.effective_principals(request)
                has_permission = authz_policy.permits(service_impl, principals, permission_requested)

                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.debug("%s - AUTHN policy configurations:", type(self).__name__)
                    base_attr = [attr for attr in dir(authn_policy.cookie) if not attr.startswith("_")]
                    for attr_name in base_attr:
                        LOGGER.debug("  %s: %s", attr_name, getattr(authn_policy.cookie, attr_name))

                LOGGER.info("User %s resolved with %s '%s' access to [%s]",
                            request.user, "allowed" if has_permission else "denied",
                            permission_requested, request.path)
                if has_permission:
                    return  # allowed
            else:
                LOGGER.debug("No permission requested. Request could not be mapped to any permission for service.")

            if request.user is None:
                error_base = HTTPUnauthorized
                error_desc = "Not authorized to access this resource. Missing user authentication."
                error_kw = {"headers": get_authenticate_headers(request)}
            else:
                error_base = HTTPForbidden
                error_desc = "Not authorized to access this resource. User does not meet required permissions."
                error_kw = {}
            raise OWSAccessForbidden(error_desc, status_base=error_base, **error_kw)

    def update_request_cookies(self, request):
        """
        Ensure login of the user and update the request cookies if Twitcher is in a special configuration.

        Only update if ``MAGPIE_COOKIE_NAME`` is missing and is retrievable from ``access_token`` field within the
        ``Authorization`` header. Counter-validate the login procedure by calling Magpie's ``/session`` which should
        indicate if there is a logged user.
        """
        settings = get_settings(request)
        token_name = get_constant("MAGPIE_COOKIE_NAME", settings_container=settings)
        if "Authorization" in request.headers and token_name not in request.cookies:
            magpie_prov = request.params.get("provider_name", get_constant("MAGPIE_DEFAULT_PROVIDER", settings))
            magpie_path = ProviderSigninAPI.path.format(provider_name=magpie_prov)
            magpie_auth = "{}{}".format(self.magpie_url, magpie_path)
            headers = dict(request.headers)
            headers.update({"Homepage-Route": "/session", "Accept": CONTENT_TYPE_JSON})
            session_resp = requests.get(magpie_auth, headers=headers, verify=self.twitcher_ssl_verify)
            if session_resp.status_code != HTTPOk.code:
                raise OWSAccessForbidden("Not authorized to access this resource. "
                                         "Provider login failed with following reason: [{}]."
                                         .format(session_resp.reason))

            # use specific domain to differentiate between `.{hostname}` and `{hostname}` variations if applicable
            request_cookies = session_resp.request._cookies  # noqa  # pylint: disable=W0212
            magpie_cookies = list(filter(lambda cookie: cookie.name == token_name, request_cookies))
            magpie_domain = urlparse(self.magpie_url).hostname if len(magpie_cookies) > 1 else None
            session_cookies = RequestsCookieJar.get(request_cookies, token_name, domain=magpie_domain)
            if not session_resp.json().get("authenticated") or not session_cookies:
                raise OWSAccessForbidden("Not authorized to access this resource. "
                                         "Session authentication could not be verified.")
            request.cookies.update({token_name: session_cookies})
