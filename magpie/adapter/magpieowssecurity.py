import requests
from pyramid.authentication import IAuthenticationPolicy
from pyramid.authorization import IAuthorizationPolicy
from pyramid.httpexceptions import HTTPForbidden, HTTPNotFound, HTTPOk
from pyramid.settings import asbool
from requests.cookies import RequestsCookieJar
from six.moves.urllib.parse import urlparse

from magpie.api.exception import evaluate_call, verify_param
from magpie.api.schemas import ProviderSigninAPI
from magpie.constants import get_constant
from magpie.models import Service
from magpie.permissions import Permission
from magpie.services import service_factory
from magpie.utils import CONTENT_TYPE_JSON, get_logger, get_magpie_url, get_settings

# twitcher available only when this module is imported from it
from twitcher.owsexceptions import OWSAccessForbidden  # noqa
from twitcher.owssecurity import OWSSecurityInterface  # noqa
from twitcher.utils import parse_service_name  # noqa

LOGGER = get_logger("TWITCHER")


class MagpieOWSSecurity(OWSSecurityInterface):

    def __init__(self, request):
        super(MagpieOWSSecurity, self).__init__()
        self.magpie_url = get_magpie_url(request)
        self.settings = get_settings(request)
        self.twitcher_ssl_verify = asbool(self.settings.get("twitcher.ows_proxy_ssl_verify", True))
        self.twitcher_protected_path = self.settings.get("twitcher.ows_proxy_protected_path", "/ows")

    def check_request(self, request):
        if request.path.startswith(self.twitcher_protected_path):
            service_name = parse_service_name(request.path, self.twitcher_protected_path)
            service = evaluate_call(lambda: Service.by_service_name(service_name, db_session=request.db),
                                    fallback=lambda: request.db.rollback(),
                                    http_error=HTTPForbidden, msg_on_fail="Service query by name refused by db.")
            verify_param(service, not_none=True, http_error=HTTPNotFound, msg_on_fail="Service name not found.")

            # return a specific type of service, ex: ServiceWPS with all the acl (loaded according to the service_type)
            service_specific = service_factory(service, request)
            # should contain all the acl, this the only thing important
            # parse request (GET/POST) to get the permission requested for that service
            permission_requested = service_specific.permission_requested()
            # convert permission enum to str for comparison
            permission_requested = Permission.get(permission_requested).value if permission_requested else None

            if permission_requested:
                LOGGER.info("'%s' request '%s' permission on '%s'", request.user, permission_requested, request.path)
                self.update_request_cookies(request)
                authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
                authz_policy = request.registry.queryUtility(IAuthorizationPolicy)
                principals = authn_policy.effective_principals(request)
                has_permission = authz_policy.permits(service_specific, principals, permission_requested)

                LOGGER.debug("%s - AUTHN policy configurations:", type(self).__name__)
                base_attr = [attr for attr in dir(authn_policy.cookie) if not attr.startswith("_")]
                for attr_name in base_attr:
                    LOGGER.debug("  %s: %s", attr_name, getattr(authn_policy.cookie, attr_name))

                if not has_permission:
                    raise OWSAccessForbidden("Not authorized to access this resource. "
                                             "User does not meet required permissions.")

    def update_request_cookies(self, request):
        """
        Ensure login of the user and update the request cookies if Twitcher is in a special configuration.

        Only update if `MAGPIE_COOKIE_NAME` is missing and is retrievable from `access_token` in `Authorization` header.
        Counter-validate the login procedure by calling Magpie's `/session` which should indicated a logged user.
        """
        token_name = get_constant("MAGPIE_COOKIE_NAME", settings_name=request.registry.settings)
        if "Authorization" in request.headers and token_name not in request.cookies:
            magpie_prov = request.params.get("provider", "WSO2")
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
