import logging
from typing import TYPE_CHECKING

import requests
from beaker.cache import cache_region, cache_regions
from pyramid.authentication import IAuthenticationPolicy
from pyramid.authorization import IAuthorizationPolicy
from pyramid.httpexceptions import HTTPForbidden, HTTPNotFound, HTTPOk, HTTPUnauthorized
from pyramid.settings import asbool
from requests.cookies import RequestsCookieJar
from six.moves.urllib.parse import urlparse

from magpie.api.exception import evaluate_call, verify_param
from magpie.api.schemas import ProviderSigninAPI
from magpie.constants import get_constant
from magpie.models import Service
from magpie.permissions import Permission
from magpie.services import invalidate_service, service_factory
from magpie.utils import CONTENT_TYPE_JSON, get_authenticate_headers, get_logger, get_magpie_url, get_settings

# WARNING:
#   Twitcher available only when this module is imported from it.
#   It is installed during tests for evaluation.
#   Module 'magpie.adapter' should not be imported from 'magpie' package.
from twitcher.owsexceptions import OWSAccessForbidden  # noqa
from twitcher.owssecurity import OWSSecurityInterface  # noqa
from twitcher.utils import parse_service_name  # noqa

LOGGER = get_logger("TWITCHER")
if TYPE_CHECKING:
    from typing import Dict, NoReturn, Optional, Tuple

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

        If the cache is not hit (expired timeout or new key entry), calls :meth:`get_service` to retrieve the actual
        :class:`ServiceInterface` implementation. Otherwise, returns the cached service to avoid SQL queries.

        .. note::
            Function arguments are required to generate caching keys by which cached elements will be retrieved.

        .. seealso::
            - :meth:`magpie.adapter.magpieowssecurity.MagpieOWSSecurity.get_service`
            - :meth:`magpie.adapter.magpieservice.MagpieServiceStore.fetch_by_name`
        """
        service = evaluate_call(lambda: Service.by_service_name(service_name, db_session=self.request.db),
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
            invalidate_service(service_name)

        # retrieve the implementation and the service data contained in the database entry
        service_impl, service_data = self._get_service_cached(service_name)

        # because the database service *could* be linked to cached item, expired session creates unbound object
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

        return service_impl

    def check_request(self, request):
        # type: (Request) -> Optional[NoReturn]
        """
        Verifies if the request user has access to the targeted resource according to parent service and permissions.

        If the request path corresponds to configured `Twitcher` proxy, evaluate the :term:`ACL`.
        Otherwise, ignore request access validation.

        In the case `Twitcher` proxy path is matched, the :term:`Logged User` **MUST** be allowed access following
        :term:`Effective Permissions` resolution via :term:`ACL`. Otherwise, :exception:`OWSForbidden` is raised.
        Failing to parse the request or any underlying component also raises that exception.

        :raises OWSForbidden: if user does not have access to the targeted resource under the service.
        :returns: nothing if user has access.
        """
        if request.path.startswith(self.twitcher_protected_path):
            service_impl = self.get_service(request)
            # should contain all the acl, this the only thing important
            # parse request (GET/POST) to get the permission requested for that service
            permission_requested = service_impl.permission_requested()
            # convert permission enum to str for comparison
            permission_requested = Permission.get(permission_requested).value if permission_requested else None

            if permission_requested:
                LOGGER.info("'%s' request '%s' permission on '%s'", request.user, permission_requested, request.path)
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

                if has_permission:
                    return  # allowed

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
