from magpie.definitions.pyramid_definitions import *
from magpie.definitions.ziggurat_definitions import *
from magpie.definitions.twitcher_definitions import *
from magpie.adapter.magpieowssecurity import *
from magpie.adapter.magpieservice import *
from magpie.models import get_user
from magpie.security import auth_config_from_settings
from magpie.db import *
import logging
logger = logging.getLogger(__name__)


class MagpieAdapter(AdapterInterface):

    def servicestore_factory(self, registry, database=None, headers=None):
        return MagpieServiceStore(registry=registry, headers=headers)

    def owssecurity_factory(self, registry):
        # TODO For magpie we cannot store the servicestore object since the constructor need a header with token
        # taken from the request... maybe we should check for that?!?
        #return MagpieOWSSecurity(tokenstore_factory(registry), servicestore_factory(registry))
        return MagpieOWSSecurity()

    def configurator_factory(self, settings):
        # Disable rpcinterface which is conflicting with postgres db
        settings['twitcher.rpcinterface'] = False

        logger.info('Loading MagpieAdapter config')
        config = auth_config_from_settings(settings)
        config.set_request_property(get_user, 'user', reify=True)
        return config

    def owsproxy_config(self, settings, config):
        logger.info('Loading MagpieAdapter owsproxy config')
        protected_path = settings.get('twitcher.ows_proxy_protected_path', '/ows')

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

        logger.info('Adding MagpieAdapter owsproxy routes and views')
        config.add_route('owsproxy', protected_path + '/{service_name}')
        config.add_route('owsproxy_extra', protected_path + '/{service_name}/{extra_path:.*}')
        config.add_route('owsproxy_secured', protected_path + '/{service_name}/{access_token}')

        config.add_view(owsproxy, route_name='owsproxy')
        config.add_view(owsproxy, route_name='owsproxy_extra')
        config.add_view(owsproxy, route_name='owsproxy_secured')
