import copy
import inspect
import re
import warnings
from typing import TYPE_CHECKING

import requests
import six
from pyramid.authentication import IAuthenticationPolicy
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPException,
    HTTPForbidden,
    HTTPOk,
    HTTPServiceUnavailable,
    HTTPUnauthorized
)
from pyramid.request import Request
from pyramid.response import Response
from pyramid_beaker import set_cache_regions_from_settings
from requests.exceptions import HTTPError
from six.moves.urllib.parse import parse_qsl, urlparse

from magpie.__meta__ import __version__ as magpie_version
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.api.exception import evaluate_call, raise_http, valid_http, verify_param
from magpie.api.generic import get_request_info
from magpie.api.schemas import SigninAPI
from magpie.app import setup_magpie_configs
from magpie.compat import LooseVersion
from magpie.constants import get_constant
from magpie.security import get_auth_config
from magpie.utils import (
    CONTENT_TYPE_JSON,
    SingletonMeta,
    get_cookies,
    get_json,
    get_logger,
    get_magpie_url,
    get_settings,
    import_target,
    is_json_body,
    normalize_field_pattern,
    setup_cache_settings,
    setup_pyramid_config,
    setup_session_config
)

# WARNING:
#   Twitcher available only when this module is imported from it.
#   It is installed during tests for evaluation.
#   Module 'magpie.adapter' should not be imported from 'magpie' package.
from twitcher.__version__ import __version__ as twitcher_version  # noqa
from twitcher.adapter.base import AdapterInterface  # noqa
from twitcher.owsproxy import owsproxy_defaultconfig  # noqa

try:
    from twitcher.owsproxy import send_request  # noqa  # Twitcher >= 0.8.0
except ImportError:
    # old reference provides unused extra arguments, but otherwise remain the same implementation
    from twitcher.owsproxy import _send_request as send_request  # noqa

    warnings.warn(
        "Older version of Twitcher detected. Using old references as fallback for backward compatibility support."
        "Consider updating to a more recent version of Twitcher."
        "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
        ImportWarning
    )


if LooseVersion(twitcher_version) >= LooseVersion("0.6.0"):
    from twitcher.owsregistry import OWSRegistry  # noqa  # pylint: disable=E0611  # Twitcher >= 0.6.x

    if LooseVersion(twitcher_version) >= LooseVersion("0.9.0"):
        warnings.warn(
            "This Magpie version is not guaranteed to work with newer versions of Twitcher. "
            "This Magpie version offers compatibility with Twitcher 0.6.x through 0.8.x."
            "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
            ImportWarning
        )
    elif LooseVersion(twitcher_version) < LooseVersion("0.7.0"):
        warnings.warn(
            "This Magpie version offers more capabilities than Twitcher 0.6.x is able to provide. "
            "Consider updating to more recent Twitcher 0.7.x to make use of new functionalities. "
            "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
            ImportWarning
        )

if LooseVersion(twitcher_version) < LooseVersion("0.6.0"):
    warnings.warn(
        "This Magpie version is not guaranteed to work with versions prior to Twitcher 0.6.x. "
        "It is recommended to either use more recent Twitcher 0.6.x version or revert back "
        "to older Magpie < 3.18 in order to use Twitcher 0.5.x versions. "
        "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
        ImportWarning
    )
if LooseVersion(twitcher_version) == LooseVersion("0.6.0"):
    warnings.warn(
        "Twitcher 0.6.0 exact version does not have complete compatibility support for MagpieAdapter. "
        "It is recommended to either revert to Twitcher 0.5.x and previous Magpie < 3.18 version, "
        "or use a higher Twitcher 0.6.x version. "
        "Current package versions are (Twitcher: {}, Magpie: {})".format(twitcher_version, magpie_version),
        ImportWarning
    )

if TYPE_CHECKING:
    from typing import Optional, Union

    from pyramid.authentication import AuthTktCookieHelper
    from pyramid.config import Configurator

    from magpie.models import Resource
    from magpie.services import ServiceInterface as MagpieService
    from magpie.typedefs import (
        JSON,
        AnyResponseType,
        AnySettingsContainer,
        ServiceConfigItem,
        ServiceHookConfigItem,
        ServiceHookType,
        Str
    )

    from twitcher.models.service import ServiceConfig  # noqa  # pylint: disable=E0611  # Twitcher >= 0.6.3
    from twitcher.store import AccessTokenStoreInterface  # noqa  # pylint: disable=E0611  # Twitcher <= 0.5.x

LOGGER = get_logger("TWITCHER|{}".format(__name__))


def verify_user(request):
    # type: (Request) -> HTTPException
    """
    Verifies that a valid user authentication on the pointed ``Magpie`` instance (via configuration) also results into a
    valid user authentication with the current ``Twitcher`` instance to ensure settings match between them.

    :param request: an HTTP request with valid authentication token/cookie credentials.
    :return: appropriate HTTP success or error response with details about the result.
    """
    magpie_url = get_magpie_url(request)

    def try_login():
        # type: () -> Union[AnyResponseType, HTTPError]
        try:
            params = dict(parse_qsl(urlparse(request.url).query))
            if is_json_body(request.text) and not params:
                return requests.post(magpie_url + SigninAPI.path, json=request.json, timeout=5,
                                     headers={"Content-Type": CONTENT_TYPE_JSON, "Accept": CONTENT_TYPE_JSON})
            return requests.get(magpie_url + SigninAPI.path, data=request.text, params=params, timeout=5)
        except HTTPError as exc:
            if getattr(exc, "status_code", 500) >= 500:
                raise
            return exc

    # must generate request metadata manually because Twitcher
    # won't have Magpie's tween that builds it automatically
    info = get_request_info(request)
    resp = evaluate_call(lambda: try_login(),
                         http_error=HTTPServiceUnavailable, metadata=info,
                         content={"magpie_url": magpie_url}, content_type=CONTENT_TYPE_JSON,
                         msg_on_fail="Could not obtain response from Magpie to validate login.")
    try:
        verify_param(resp.status_code, is_equal=True, param_compare=HTTPOk.code, param_name="status_code",
                     http_error=HTTPBadRequest, content={"response": get_json(resp)}, content_type=CONTENT_TYPE_JSON,
                     msg_on_fail="Failed Magpie login due to invalid or missing parameters.", metadata=info)
        authn_policy = request.registry.queryUtility(IAuthenticationPolicy)  # noqa
        authn_cookie = authn_policy.cookie  # type: AuthTktCookieHelper
        cookie_name = authn_cookie.cookie_name
        req_cookies = get_cookies(request)
        resp_cookies = get_cookies(resp)
        verify_param(cookie_name, is_in=True, param_compare=req_cookies, with_param=False,
                     http_error=HTTPUnauthorized, content_type=CONTENT_TYPE_JSON, metadata=info,
                     msg_on_fail="Authentication cookies missing from request to validate against Magpie instance.")
        verify_param(cookie_name, is_in=True, param_compare=resp_cookies, with_param=False,
                     http_error=HTTPUnauthorized, content_type=CONTENT_TYPE_JSON, metadata=info,
                     msg_on_fail="Authentication cookies missing from response to validate against Magpie instance.")
        twitcher_identity = authn_cookie.identify(request)
        verify_param(twitcher_identity, not_none=True, with_param=False,
                     http_error=HTTPUnauthorized, content_type=CONTENT_TYPE_JSON, metadata=info,
                     msg_on_fail="Authentication failed from Twitcher policy.")
        twitcher_user_id = twitcher_identity["userid"]
        verify_param(twitcher_user_id, not_none=True, is_type=True, param_compare=int, with_param=False,
                     http_error=HTTPUnauthorized, content_type=CONTENT_TYPE_JSON, metadata=info,
                     msg_on_fail="Authentication failed from Twitcher policy.")
        cookie_value = resp_cookies[cookie_name]
        cookie_userid_type = cookie_value.split("!userid_type:")[-1]
        cookie_decode = authn_cookie.userid_type_decoders[cookie_userid_type]
        cookie_ip = "0.0.0.0"  # nosec: B104
        result = authn_cookie.parse_ticket(authn_cookie.secret, cookie_value, cookie_ip, authn_cookie.hashalg)
        magpie_user_id = cookie_decode(result[1])
        verify_param(magpie_user_id, is_equal=True, param_compare=twitcher_user_id, with_param=False,
                     http_error=HTTPForbidden, content_type=CONTENT_TYPE_JSON, metadata=info,
                     msg_on_fail="Twitcher login incompatible with Magpie login.")
    except HTTPException as resp_err:
        return resp_err
    except Exception:
        return raise_http(HTTPForbidden, content_type=CONTENT_TYPE_JSON, metadata=info,
                          detail="Twitcher login incompatible with Magpie login.", nothrow=True)
    return valid_http(HTTPOk, detail="Twitcher login verified successfully with Magpie login.")


@six.add_metaclass(SingletonMeta)
class MagpieAdapter(AdapterInterface):
    # pylint: disable: W0223,W0612

    def __init__(self, container):
        # type: (AnySettingsContainer) -> None
        self._servicestore = None
        self._owssecurity = None
        super(MagpieAdapter, self).__init__(container)  # pylint: disable=E1101,no-member

    def reset(self):
        # type: () -> None
        self._servicestore = None
        self._owssecurity = None

    @property
    def name(self):
        # type: () -> Str
        # pylint: disable=E1101,no-member
        return AdapterInterface.name.fget(self)  # noqa

    def describe_adapter(self):
        # type: () -> JSON
        return {"name": self.name, "version": magpie_version}

    def servicestore_factory(self, request):
        # type: (Request) -> MagpieServiceStore
        if self._servicestore is None:
            self._servicestore = MagpieServiceStore(request)
        return self._servicestore

    def tokenstore_factory(self, request):
        # type: (Request) -> AccessTokenStoreInterface
        """
        Unused token store implementation.

        .. versionchanged:: 3.18
            Available only in ``Twitcher <= 0.5.x``.
        """
        raise NotImplementedError

    def owsregistry_factory(self, request):
        # type: (Request) -> OWSRegistry
        """
        Creates the :class:`OWSRegistry` implementation derived from :class:`MagpieServiceStore`.

        .. versionadded:: 3.18
            Available only in ``Twitcher >= 0.6.x``.
        """
        return OWSRegistry(self.servicestore_factory(request))

    def owssecurity_factory(self, request=None):  # noqa  # pylint: disable=W0221  # diff between Twitcher 0.5.x/0.6.x
        # type: (Optional[AnySettingsContainer]) -> MagpieOWSSecurity
        """
        Creates the :class:`OWSSecurity` implementation derived from :class:`MagpieOWSSecurity`.

        .. versionchanged:: 3.18
            Method :paramref:`request` does not exist starting in ``Twitcher >= 0.6.x``.
        """
        if self._owssecurity is None:
            self._owssecurity = MagpieOWSSecurity(request or self.settings)
        return self._owssecurity

    def owsproxy_config(self, container):
        # type: (AnySettingsContainer) -> None
        LOGGER.info("Loading MagpieAdapter owsproxy config")
        config = self.configurator_factory(container)
        owsproxy_defaultconfig(config)  # let Twitcher configure the rest normally

    def configurator_factory(self, container):  # noqa: R0201
        # type: (AnySettingsContainer) -> Configurator
        LOGGER.debug("Preparing database session.")

        settings = get_settings(container)
        setup_cache_settings(settings)  # default 'cache=off' if missing since 'pyramid_beaker' enables it otherwise
        set_cache_regions_from_settings(settings)  # parse/convert cache settings into regions understood by beaker

        # load any settings or configuration file that could provide service hook definitions
        # no need to register them since Magpie will have already done so
        # since this code runs under Twitcher, it must know about Magpie's configuration
        setup_magpie_configs(
            settings,
            setup_permissions=False,
            setup_webhooks=False,
            setup_providers=True,  # obtain "magpie.services" if any
            skip_registration=True,
        )

        # disable rpcinterface which is conflicting with postgres db
        settings["twitcher.rpcinterface"] = False

        LOGGER.info("Loading Magpie AuthN/AuthZ configuration for adapter.")
        config = get_auth_config(container)
        config.include("pyramid_beaker")
        setup_pyramid_config(config)
        setup_session_config(config)

        # add route to verify user token matching between Magpie/Twitcher
        config.add_route("verify-user", "/verify", request_method=("GET", "POST"))
        config.add_view(verify_user, route_name="verify-user")

        return config

    def _apply_hooks(self, instance, service_name, hook_type, method, path, query):
        # type: (Union[Request, Response], Str, ServiceHookType, Str, Str, Str) -> Union[Request, Response]
        """
        Executes the hooks processing chain.
        """
        svc_config = self.settings.get("magpie.services", {}).get(service_name, {})
        svc_hooks = svc_config.get("hooks", [])
        # copy to avoid (un)intentional modifications to configurations
        svc_config = copy.deepcopy(svc_config)
        svc_config["name"] = service_name  # often useful reference, but not directly in definition since dict key
        for hook_cfg in svc_hooks:
            if hook_cfg["type"] != hook_type:
                continue
            if hook_cfg["method"] not in ["*", method]:
                continue
            hook_path = normalize_field_pattern(hook_cfg["path"], escape=False)
            if not re.match(hook_path, path):
                continue
            hook_query = normalize_field_pattern(hook_cfg["query"], escape=False)
            if not re.match(hook_query, query):
                continue
            hook_target = import_target(hook_cfg["target"], default_root=get_constant("MAGPIE_PROVIDERS_HOOKS_PATH"))
            hook_qs = "?" + query if query else ""
            if not hook_target:
                LOGGER.warning("Hook matched %s (%s %s%s) but specified target [%s] could not be loaded.",
                               hook_type, method, path, hook_qs, hook_cfg["target"])
                continue
            LOGGER.debug("Hook matched %s (%s %s%s) [%s]", hook_type, method, path, hook_qs, hook_cfg["target"])
            signature = inspect.signature(hook_target)
            kwargs = {}
            if len(signature.parameters) > 1:
                hook = copy.deepcopy(hook_cfg)
                ctx = HookContext(instance, self, svc_config, hook)
                for key, val in [("service", svc_config), ("hook", hook), ("context", ctx)]:
                    if key in signature.parameters:
                        kwargs[key] = val
            try:
                instance = hook_target(instance, **kwargs)
            except Exception as exc:
                LOGGER.error("Hook failed %s (%s %s%s) [%s]",
                             hook_type, method, path, hook_qs, hook_cfg["target"], exc_info=exc)
                raise exc
        return instance

    @staticmethod
    def _proxied_service_path(request):
        # type: (Request) -> Str
        """
        Extract the request extra path of the proxied service without :term:`Twitcher` proxy prefix.
        """
        # employ the same parameter added by 'owsproxy_extra' view and used to call the proxied request
        extra_path = request.matchdict.get("extra_path", "")
        extra_path = "/" + extra_path if extra_path else ""
        return extra_path

    def request_hook(self, request, service):
        # type: (Request, ServiceConfig) -> Request
        """
        Apply modifications onto the request before sending it.

        .. versionadded:: 3.25
            Requires ``Twitcher >= 0.7.x``.

        Request members employed after this hook is called include:
        - :meth:`Request.headers`
        - :meth:`Request.method`
        - :meth:`Request.body`

        This method can modified those members to adapt the request for specific service logic.
        """
        request_path = self._proxied_service_path(request)
        request = self._apply_hooks(
            request, service["name"], "request",
            request.method, request_path, request.query_string
        )
        return request

    def response_hook(self, response, service):
        # type: (Response, ServiceConfig) -> Response
        """
        Apply modifications onto the response from sent request.

        .. versionadded:: 3.25
            Requires ``Twitcher >= 0.7.x``.

        The received response from the proxied service is normally returned directly.
        This method can modify the response to adapt it for specific service logic.
        """
        request_path = self._proxied_service_path(response.request)
        response = self._apply_hooks(
            response, service["name"], "response",
            response.request.method, request_path, response.request.query_string
        )
        return response

    def send_request(self, request, service):
        # type: (Request, ServiceConfig) -> Response
        """
        Send the request to the proxied service and handle its response.

        .. versionadded:: 3.31
            Requires ``Twitcher >= 0.8.x``.

        Because requests are sometimes handled using :mod:`requests` depending on the service type, the ``request``
        reference in the produced ``response`` is not always set. Ensure it is applied to allow :meth:`response_hook`
        retrieving it when attempting to resolve the proxied service path.
        """
        response = send_request(request, service)
        if response.request is None:
            response.request = request
        return response


class HookContext(object):
    """
    Context handlers associated to the request/response for the :term:`Service Hook` to be evaluated.

    Dispatch calls to database or other derived operations *on demand* as much as possible to minimize the impact of
    retrieving some parameters by each request that requires this hook context.
    """
    adapter = None   # type: MagpieAdapter
    request = None   # type: Request
    response = None  # type: Optional[Response]  # optional in case request hook (response not yet reached)
    config = None    # type: ServiceConfigItem   # same as 'service' parameter that can be requested directly
    hook = None      # type: ServiceHookConfigItem  # same as 'hook' parameter that can be requested directly
    _service = None  # type: Optional[MagpieService]

    def __init__(self, instance, adapter, config, hook):
        # type: (Union[Request, Response], MagpieAdapter, ServiceConfigItem, ServiceHookConfigItem) -> None
        self.adapter = adapter
        self.config = config
        self.hook = hook
        if isinstance(instance, Request):
            self.request = instance
            self.response = None
        if isinstance(instance, Response):
            self.response = instance
            self.request = instance.request

    @property
    def service(self):
        # type: () -> MagpieService
        """
        Service implementation that defines the :term:`Resource` structure and :term:`Permission` resolution method.
        """
        if not self._service:
            self._service = self.adapter.owssecurity_factory(self.request).get_service(self.request)
        return self._service

    @property
    def resource(self):
        # type: () -> Resource
        """
        Database :term:`Resource` that represents the :term:`Service` reference implementation.
        """
        return self.service.service
