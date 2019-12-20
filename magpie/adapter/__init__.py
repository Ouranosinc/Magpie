from magpie.definitions.twitcher_definitions import AdapterInterface, owsproxy_defaultconfig
from magpie.definitions.pyramid_definitions import IAuthenticationPolicy, HTTPForbidden, HTTPOk
from magpie.definitions.ziggurat_definitions import UserService
from magpie.api.schemas import SigninAPI
from magpie.api.exception import valid_http, raise_http
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.security import get_auth_config
from magpie.db import get_session_factory, get_tm_session, get_engine
from magpie.utils import get_logger, get_settings, get_magpie_url, SingletonMeta, CONTENT_TYPE_JSON
from magpie import __meta__
from pyramid_beaker import set_cache_regions_from_settings
import six
import time
import logging
import requests
LOGGER = get_logger("TWITCHER")


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
    cookie_inst = request._get_authentication_policy().cookie  # noqa: W0212
    cookie = request.cookies.get(cookie_inst.cookie_name)

    LOGGER.debug(
        "Cookie (name : {0}, secret : {1}, hashalg : {2}) : {3}".format(
            cookie_inst.cookie_name,
            cookie_inst.secret,
            cookie_inst.hashalg,
            cookie))

    if not cookie:
        LOGGER.debug('No Cookie!')
    else:
        if cookie_inst.include_ip:
            environ = request.environ
            remote_addr = environ['REMOTE_ADDR']
        else:
            remote_addr = '0.0.0.0'

        LOGGER.debug(
            "Cookie remote addr (include_ip : {0}) : {1}".format(cookie_inst.include_ip, remote_addr))

        now = time.time()
        timestamp, userid, tokens, user_data = cookie_inst.parse_ticket(
            cookie_inst.secret, cookie, remote_addr,
            cookie_inst.hashalg)

        LOGGER.debug(
            "Cookie timestamp : {0}, timeout : {1}, now : {2}".format(timestamp, cookie_inst.timeout, now))

        if cookie_inst.timeout and (
                (timestamp + cookie_inst.timeout) < now):
            # the auth_tkt data has expired
            LOGGER.debug("Cookie is expired")

        # Could raise useful exception explaining why unauthenticated_userid is None
        request._get_authentication_policy().cookie.identify(request)  # noqa: W0212


def get_user(request):
    user_id = request.unauthenticated_userid
    LOGGER.debug('Current user id is {0}'.format(user_id))

    if user_id is not None:
        user = UserService.by_id(user_id, db_session=request.db)
        LOGGER.debug(
            'Current user has been resolved has {0}'.format(user))
        return user
    elif LOGGER.isEnabledFor(logging.DEBUG):
        debug_cookie_identify(request)


def verify_user(request):
    magpie_url = get_magpie_url(request)
    resp = requests.post(magpie_url + SigninAPI.path, json=request.json,
                         headers={"Content-Type": CONTENT_TYPE_JSON, "Accept": CONTENT_TYPE_JSON})
    if resp.status_code != HTTPOk.code:
        content = {"response": resp.json()}
        return raise_http(HTTPForbidden, detail="Failed Magpie login.", content=content, nothrow=True)
    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
    result = authn_policy.cookie.identify(request)
    if result is None:
        return raise_http(HTTPForbidden, detail="Twitcher login incompatible with Magpie login.", nothrow=True)
    return valid_http(HTTPOk, detail="Twitcher login verified successfully with Magpie login.")


class MagpieAdapter(six.with_metaclass(SingletonMeta, AdapterInterface)):
    def __init__(self, container):
        self._servicestore = None
        self._owssecurity = None
        super(MagpieAdapter, self).__init__(container)

    def describe_adapter(self):
        return {"name": self.name, "version": __meta__.__version__}

    def servicestore_factory(self, request, headers=None):  # noqa: F811
        if self._servicestore is None:
            self._servicestore = MagpieServiceStore(request)
        return self._servicestore

    def owssecurity_factory(self, request):
        if self._owssecurity is None:
            self._owssecurity = MagpieOWSSecurity(request)
        return self._owssecurity

    def owsproxy_config(self, container):
        LOGGER.info("Loading MagpieAdapter owsproxy config")
        config = self.configurator_factory(container)
        owsproxy_defaultconfig(config)  # let Twitcher configure the rest normally

    def configurator_factory(self, container):  # noqa: N805
        settings = get_settings(container)
        set_cache_regions_from_settings(settings)

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
