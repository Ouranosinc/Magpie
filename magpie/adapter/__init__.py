from magpie.definitions.twitcher_definitions import AdapterInterface, owsproxy_defaultconfig
from magpie.definitions.ziggurat_definitions import UserService
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.security import get_auth_config
from magpie.db import get_session_factory, get_tm_session, get_engine
from magpie.utils import get_logger, get_settings
from magpie import __meta__
import time
import logging


LOGGER = get_logger("TWITCHER")


# noinspection PyAbstractClass, PyMethodMayBeStatic, PyUnusedLocal
class MagpieAdapter(AdapterInterface):
    def describe_adapter(self):
        return {"name": self.name(), "version": __meta__.__version__}

    def servicestore_factory(self, request, headers=None):
        return MagpieServiceStore(request)

    def owssecurity_factory(self, request):
        return MagpieOWSSecurity(request)

    def configurator_factory(self, container):
        settings = get_settings(container)

        # disable rpcinterface which is conflicting with postgres db
        settings["twitcher.rpcinterface"] = False

        LOGGER.info("Loading MagpieAdapter config")
        config = get_auth_config(container)

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

        def get_user(request):
            user_id = request.unauthenticated_userid
            LOGGER.debug('Current user id is {0}'.format(user_id))

            if user_id is not None:
                user = UserService.by_id(user_id, db_session=request.db)
                LOGGER.debug(
                    'Current user has been resolved has {0}'.format(user))
                return user
            elif LOGGER.isEnabledFor(logging.DEBUG):
                cookie_inst = request._get_authentication_policy().cookie
                cookie = request.cookies.get(cookie_inst.cookie_name)

                LOGGER.debug(
                    "Cookie (name : {0}, secret : {1}, hashalg : {2}) : {3}".
                    format(cookie_inst.cookie_name,
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
                        "Cookie remote addr (include_ip : {0}) : {1}".
                        format(cookie_inst.include_ip, remote_addr))

                    now = time.time()
                    timestamp, userid, tokens, user_data = cookie_inst.parse_ticket(
                        cookie_inst.secret, cookie, remote_addr,
                        cookie_inst.hashalg)

                    LOGGER.debug(
                        "Cookie timestamp : {0}, timeout : {1}, now : {2}".
                        format(timestamp, cookie_inst.timeout, now))

                    if cookie_inst.timeout and (
                            (timestamp + cookie_inst.timeout) < now):
                        # the auth_tkt data has expired
                        LOGGER.debug("Cookie is expired")

                    # Could raise useful exception explaining why unauthenticated_userid is None
                    request._get_authentication_policy().cookie.identify(request)

        # use same 'get_user' method as ziggurat to access 'request.user' from
        # request with auth token with exactly the same behaviour in Twitcher
        config.add_request_method(get_user, "user", reify=True)

        return config

    def owsproxy_config(self, container):
        LOGGER.info("Loading MagpieAdapter owsproxy config")
        config = self.configurator_factory(container)
        owsproxy_defaultconfig(config)  # let Twitcher configure the rest normally
