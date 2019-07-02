from magpie.definitions.twitcher_definitions import AdapterInterface, owsproxy_defaultconfig
from magpie.definitions.ziggurat_definitions import UserService
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.security import get_auth_config
from magpie.db import get_session_factory, get_tm_session, get_engine
from magpie.utils import get_logger, get_settings
from magpie import __meta__
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
            if user_id is not None:
                return UserService.by_id(user_id, db_session=request.db)

        # use same 'get_user' method as ziggurat to access 'request.user' from
        # request with auth token with exactly the same behaviour in Twitcher
        config.add_request_method(get_user, "user", reify=True)

        return config

    def owsproxy_config(self, container):
        LOGGER.info("Loading MagpieAdapter owsproxy config")
        config = self.configurator_factory(container)
        owsproxy_defaultconfig(config)  # let Twitcher configure the rest normally
