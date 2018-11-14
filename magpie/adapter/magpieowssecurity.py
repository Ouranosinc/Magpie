from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import *
from magpie.services import service_factory
from magpie.models import Service
from magpie.api.api_except import evaluate_call, verify_param
from magpie.adapter.utils import get_magpie_url
from requests.cookies import RequestsCookieJar
import requests
import logging
LOGGER = logging.getLogger("TWITCHER")


class MagpieOWSSecurity(OWSSecurityInterface):

    def __init__(self, registry):
        super(MagpieOWSSecurity, self).__init__()
        self.magpie_url = get_magpie_url(registry)
        self.twitcher_ssl_verify = asbool(registry.settings.get('twitcher.ows_proxy_ssl_verify', True))
        self.twitcher_protected_path = registry.settings.get('twitcher.ows_proxy_protected_path', '/ows')

    def check_request(self, request):
        if request.path.startswith(self.twitcher_protected_path):
            service_name = parse_service_name(request.path, self.twitcher_protected_path)
            service = evaluate_call(lambda: Service.by_service_name(service_name, db_session=request.db),
                                    fallback=lambda: request.db.rollback(),
                                    httpError=HTTPForbidden, msgOnFail="Service query by name refused by db")
            verify_param(service, notNone=True, httpError=HTTPNotFound, msgOnFail="Service name not found in db")

            # return a specific type of service, ex: ServiceWPS with all the acl (loaded according to the service_type)
            service_specific = service_factory(service, request)
            # should contain all the acl, this the only thing important
            # parse request (GET/POST) to get the permission requested for that service
            permission_requested = service_specific.permission_requested()

            if permission_requested:
                self.update_request_cookies(request)
                authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
                authz_policy = request.registry.queryUtility(IAuthorizationPolicy)
                principals = authn_policy.effective_principals(request)
                has_permission = authz_policy.permits(service_specific, principals, permission_requested)
                if not has_permission:
                    raise OWSAccessForbidden("Not authorized to access this resource.")

    def update_request_cookies(self, request):
        """
        Ensure login of the user and update the request cookies if twitcher is in a special configuration.
        Only update if Magpie `auth_tkt` is missing and can be retrieved from `access_token` in `Authorization` header.
        Counter-validate the login procedure by calling Magpie's `/session` which should indicated a logged user.
        """
        not_default = get_twitcher_configuration(request.registry.settings) != TWITCHER_CONFIGURATION_DEFAULT
        if not_default and 'Authorization' in request.headers and 'auth_tkt' not in request.cookies:
            magpie_url = request.registry.settings.get('magpie.url')
            magpie_prov = request.params.get('provider', 'WSO2')
            magpie_auth = '{host}/providers/{provider}/signin'.format(host=magpie_url, provider=magpie_prov)
            headers = dict(request.headers)
            headers.update({'Homepage-Route': '/session', 'Accept': 'application/json'})
            session_resp = requests.get(magpie_auth, headers=headers, verify=self.twitcher_ssl_verify)
            if session_resp.status_code != HTTPOk.code:
                raise session_resp.raise_for_status()
            # noinspection PyProtectedMember
            session_cookies = RequestsCookieJar.get(session_resp.request._cookies, 'auth_tkt')
            if not session_resp.json().get('authenticated') or not session_cookies:
                raise OWSAccessForbidden("Not authorized to access this resource.")
            request.cookies.update({'auth_tkt': session_cookies})
