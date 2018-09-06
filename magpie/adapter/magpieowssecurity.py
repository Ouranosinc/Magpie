import tempfile
from magpie.definitions.twitcher_definitions import *
from magpie.definitions.pyramid_definitions import *
from magpie.services import service_factory
from magpie.models import Service
from magpie.api.api_except import evaluate_call, verify_param

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
                authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
                authz_policy = request.registry.queryUtility(IAuthorizationPolicy)
                principals = authn_policy.effective_principals(request)
                has_permission = authz_policy.permits(service_specific, principals, permission_requested)
                if not has_permission:
                    raise OWSAccessForbidden("Not authorized to access this resource.")
