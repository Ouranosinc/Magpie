import logging
import time
from typing import TYPE_CHECKING

import requests
import six
from pyramid.authentication import IAuthenticationPolicy
from pyramid.httpexceptions import HTTPForbidden, HTTPOk
from pyramid_beaker import set_cache_regions_from_settings
from ziggurat_foundations.models.services.user import UserService

from magpie import __meta__
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.api.exception import raise_http, valid_http
from magpie.api.schemas import SigninAPI
from magpie.db import get_engine, get_session_factory, get_tm_session
from magpie.security import get_auth_config
from magpie.utils import (
    CONTENT_TYPE_JSON,
    SingletonMeta,
    get_logger,
    get_magpie_url,
    get_settings,
    setup_cache_settings
)

# WARNING:
#   Twitcher available only when this module is imported from it.
#   It is installed during tests for evaluation.
#   Module 'magpie.adapter' should not be imported from 'magpie' package.
from twitcher.adapter.base import AdapterInterface  # noqa
from twitcher.owsproxy import owsproxy_defaultconfig  # noqa

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Optional

    from pyramid.config import Configurator
    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request

    from magpie.models import User
    from magpie.typedefs import JSON, AnySettingsContainer, Str

    from twitcher.store import AccessTokenStoreInterface  # noqa

LOGGER = get_logger("TWITCHER|{}".format(__name__))


def debug_cookie_identify(request):
    """
    Logs debug information about request cookie.

    .. WARNING::

        This function is intended for debugging purposes only. It reveals sensible configuration information.

    Re-implements basic functionality of :func:`pyramid.AuthTktAuthenticationPolicy.cookie.identify` called via
    :func:`request.unauthenticated_userid` within :func:`get_user` to provide additional logging.

    .. seealso::
        - :class:`pyramid.authentication.AuthTktCookieHelper`
        - :class:`pyramid.authentication.AuthTktAuthenticationPolicy`
    """
    # pylint: disable=W0212
    cookie_inst = request._get_authentication_policy().cookie  # noqa: W0212
    cookie = request.cookies.get(cookie_inst.cookie_name)

    LOGGER.debug("Cookie (name: %s, secret: %s, hash-alg: %s) : %s",
                 cookie_inst.cookie_name, cookie_inst.secret, cookie_inst.hashalg, cookie)

    if not cookie:
        LOGGER.debug("No Cookie!")
    else:
        if cookie_inst.include_ip:
            environ = request.environ
            remote_addr = environ["REMOTE_ADDR"]
        else:
            remote_addr = "0.0.0.0"  # nosec # only for log debugging

        LOGGER.debug("Cookie remote addr (include_ip: %s) : %s", cookie_inst.include_ip, remote_addr)
        now = time.time()
        timestamp, _, _, _ = cookie_inst.parse_ticket(cookie_inst.secret, cookie, remote_addr, cookie_inst.hashalg)
        LOGGER.debug("Cookie timestamp: %s, timeout: %s, now: %s", timestamp, cookie_inst.timeout, now)

        if cookie_inst.timeout and ((timestamp + cookie_inst.timeout) < now):
            # the auth_tkt data has expired
            LOGGER.debug("Cookie is expired")

        # Could raise useful exception explaining why unauthenticated_userid is None
        request._get_authentication_policy().cookie.identify(request)  # noqa: W0212


def get_user(request):
    # type: (Request) -> Optional[User]
    """
    Obtains the authenticated user from the request (if any).

    :param request: incoming HTTP request potentially containing authentication definitions.
    :return: the authenticated user if parameters were valid (good credentials, not expired, etc.) or ``None``.
    """
    user_id = request.unauthenticated_userid
    LOGGER.debug("Current user ID is '%s', attempt resolving user...", user_id)

    if user_id is not None:
        user = UserService.by_id(user_id, db_session=request.db)
        LOGGER.debug("Current user has been resolved as '%s'", user)
        return user
    if LOGGER.isEnabledFor(logging.DEBUG):
        debug_cookie_identify(request)
    return None


def verify_user(request):
    # type: (Request) -> HTTPException
    """
    Verifies that a valid user authentication on the pointed ``Magpie`` instance (via configuration) also results into a
    valid user authentication with the current ``Twitcher`` instance to ensure settings match between them.

    :param request: an HTTP request with valid authentication token/cookie credentials.
    :return: appropriate HTTP success or error response with details about the result.
    """
    magpie_url = get_magpie_url(request)
    resp = requests.post(magpie_url + SigninAPI.path, json=request.json,
                         headers={"Content-Type": CONTENT_TYPE_JSON, "Accept": CONTENT_TYPE_JSON})
    if resp.status_code != HTTPOk.code:
        content = {"response": resp.json()}
        return raise_http(HTTPForbidden, detail="Failed Magpie login.", content=content, nothrow=True)  # noqa
    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)  # noqa
    result = authn_policy.cookie.identify(request)
    if result is None:
        return raise_http(HTTPForbidden, detail="Twitcher login incompatible with Magpie login.", nothrow=True)  # noqa
    return valid_http(HTTPOk, detail="Twitcher login verified successfully with Magpie login.")


@six.add_metaclass(SingletonMeta)
class MagpieAdapter(AdapterInterface):
    # pylint: disable: W0223,W0612

    def __init__(self, container):
        self._servicestore = None
        self._owssecurity = None
        super(MagpieAdapter, self).__init__(container)  # pylint: disable=E1101,no-member

    @property
    def name(self):
        # type: () -> Str
        # pylint: disable=E1101,no-member
        return AdapterInterface.name.fget(self)  # noqa

    def describe_adapter(self):
        # type: () -> JSON
        return {"name": self.name, "version": __meta__.__version__}

    def servicestore_factory(self, request):
        # type: (Request) -> MagpieServiceStore
        if self._servicestore is None:
            self._servicestore = MagpieServiceStore(request)
        return self._servicestore

    def tokenstore_factory(self, request):
        # type: (Request) -> AccessTokenStoreInterface
        raise NotImplementedError

    def owssecurity_factory(self, request):
        # type: (AnySettingsContainer) -> MagpieOWSSecurity
        if self._owssecurity is None:
            self._owssecurity = MagpieOWSSecurity(request)
        return self._owssecurity

    def owsproxy_config(self, container):
        # type: (AnySettingsContainer) -> None
        LOGGER.info("Loading MagpieAdapter owsproxy config")
        config = self.configurator_factory(container)
        owsproxy_defaultconfig(config)  # let Twitcher configure the rest normally

    def configurator_factory(self, container):  # noqa: N805, R0201
        # type: (AnySettingsContainer) -> Configurator
        settings = get_settings(container)
        setup_cache_settings(settings)  # default 'cache=off' if missing since 'pyramid_beaker' enables it otherwise
        set_cache_regions_from_settings(settings)  # parse/convert cache settings into regions understood by beaker

        # disable rpcinterface which is conflicting with postgres db
        settings["twitcher.rpcinterface"] = False

        LOGGER.info("Loading MagpieAdapter config")
        config = get_auth_config(container)
        config.include("pyramid_beaker")

        # use pyramid_tm to hook the transaction lifecycle to the request
        # make request.db available for use in Pyramid
        config.include("pyramid_tm")
        session_factory = get_session_factory(get_engine(settings))
        config.registry["dbsession_factory"] = session_factory
        config.add_request_method(
            # r.tm is the transaction manager used by pyramid_tm
            lambda r: get_tm_session(session_factory, r.tm),
            "db",
            reify=True
        )

        # use same 'get_user' method as ziggurat to access 'request.user' from
        # request with auth token with exactly the same behaviour in Twitcher
        config.add_request_method(get_user, "user", reify=True)

        # add route to verify user token matching between Magpie/Twitcher
        config.add_route("verify-user", "/verify")
        config.add_view(verify_user, route_name="verify-user")

        return config
