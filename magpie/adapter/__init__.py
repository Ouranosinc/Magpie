from magpie.definitions.twitcher_definitions import DefaultAdapter, AdapterInterface, owsproxy
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.models import get_user
from magpie.security import auth_config_from_settings
from magpie.db import get_session_factory, get_tm_session, get_engine
from magpie.utils import get_logger
from magpie import __meta__
LOGGER = get_logger("TWITCHER")


# noinspection PyAbstractClass, PyMethodMayBeStatic, PyUnusedLocal
class MagpieAdapter(AdapterInterface):
    def describe_adapter(self):
        return {"name": self.__class__.__name__, "version": __meta__.__version__}

    def servicestore_factory(self, registry, headers=None):
        return MagpieServiceStore(registry=registry)

    def processstore_factory(self, registry):
        # import here to avoid import errors on default twitcher not implementing processes
        from magpie.adapter.magpieprocess import MagpieProcessStore
        return MagpieProcessStore(registry=registry)

    def jobstore_factory(self, registry):
        # no reimplementation of jobs on magpie side
        # simply return the default twitcher job store
        return DefaultAdapter().jobstore_factory(registry)

    def owssecurity_factory(self, registry):
        return MagpieOWSSecurity(registry=registry)

    def configurator_factory(self, settings):
        # Disable rpcinterface which is conflicting with postgres db
        settings['twitcher.rpcinterface'] = False

        LOGGER.info('Loading MagpieAdapter config')
        config = auth_config_from_settings(settings)
        config.add_request_method(get_user, 'user', reify=True)
        self.owsproxy_config(settings, config)
        return config

    def owsproxy_config(self, settings, config):
        LOGGER.info('Loading MagpieAdapter owsproxy config')

        # use pyramid_tm to hook the transaction lifecycle to the request
        config.include('pyramid_tm')

        session_factory = get_session_factory(get_engine(settings))
        config.registry['dbsession_factory'] = session_factory

        # make request.db available for use in Pyramid
        config.add_request_method(
            # r.tm is the transaction manager used by pyramid_tm
            lambda r: get_tm_session(session_factory, r.tm),
            'db',
            reify=True
        )

        LOGGER.info('Adding MagpieAdapter owsproxy routes and views')
        protected_path = settings.get('twitcher.ows_proxy_protected_path', '/ows')
        config.add_route('owsproxy', protected_path + '/{service_name}')
        config.add_route('owsproxy_extra', protected_path + '/{service_name}/{extra_path:.*}')
        config.add_route('owsproxy_secured', protected_path + '/{service_name}/{access_token}')

        config.add_view(owsproxy, route_name='owsproxy')
        config.add_view(owsproxy, route_name='owsproxy_extra')
        config.add_view(owsproxy, route_name='owsproxy_secured')
