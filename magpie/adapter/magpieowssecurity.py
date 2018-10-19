from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import *
from magpie.services import service_factory
from magpie.models import Service
from magpie.api.api_except import evaluate_call, verify_param
import requests
import logging
LOGGER = logging.getLogger("TWITCHER")


class MagpieOWSSecurity(OWSSecurityInterface):

    def check_request(self, request):
        twitcher_protected_path = request.registry.settings.get('twitcher.ows_proxy_protected_path', '/ows')
        if request.path.startswith(twitcher_protected_path):
            service_name = parse_service_name(request.path, twitcher_protected_path)
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

    @staticmethod
    def update_request_cookies(request):
        """
        Ensure login of the user and update the request cookies if twitcher is in a special configuration.
        Only update if Magpie `auth_tkt` is missing and can be retrieved from `access_token` in `Authorization` header.
        Counter-validate the login procedure by calling Magpie's `/session` which should indicated a logged user.
        """
        not_default = get_twitcher_configuration(request.registry.settings) != TWITCHER_CONFIGURATION_DEFAULT
        if not_default and 'Authorization' in request.headers and 'auth_tkt' not in request.cookies:
            ssl_verify = asbool(request.registry.settings.get('twitcher.ows_proxy_ssl_verify', True))
            magpie_url = request.registry.settings.get('magpie.url')
            magpie_prov = request.params.get('provider', 'WSO2')
            magpie_auth = '{host}/providers/{provider}/signin'.format(host=magpie_url, provider=magpie_prov)
            headers = request.headers
            headers['Homepage-Route'] = '/session'
            headers['Accept'] = 'application/json'
            auth_resp = requests.get(magpie_auth, headers=headers, verify=ssl_verify)
            if auth_resp.status_code != HTTPOk.code:
                raise auth_resp.raise_for_status()
            if not auth_resp.json().get('authenticated') or 'auth_tkt' not in auth_resp.request._cookies:
                raise OWSAccessForbidden("Not authorized to access this resource.")
            request.cookies['auth_tkt'] = auth_resp.request._cookies['auth_tkt']
