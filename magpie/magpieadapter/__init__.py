import logging
import os
import sys
from twitcher.adapter.base import AdapterInterface
from twitcher.owsproxy import owsproxy


this_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, this_dir)

logger = logging.getLogger(__name__)


class MagpieAdapter(AdapterInterface):

    def servicestore_factory(self, registry, database=None):
        from magpie.magpieadapter.magpieservice import MagpieServiceStore
        return MagpieServiceStore(registry=registry)

    def owssecurity_factory(self, registry):
        from magpie.magpieadapter.magpieowssecurity import MagpieOWSSecurity
        return MagpieOWSSecurity()

    def configurator_factory(self, settings):
        from pyramid.config import Configurator
        from pyramid.authentication import AuthTktAuthenticationPolicy
        from pyramid.authorization import ACLAuthorizationPolicy
        from ziggurat_foundations.models import groupfinder

        magpie_secret = settings['magpie.secret']

        # Disable rpcinterface which is conflicting with postgres db
        settings['twitcher.rpcinterface'] = False

        authn_policy = AuthTktAuthenticationPolicy(
            magpie_secret,
            callback=groupfinder,
        )
        authz_policy = ACLAuthorizationPolicy()

        config = Configurator(
            settings=settings,
            authentication_policy=authn_policy,
            authorization_policy=authz_policy
        )

        from magpie.models import get_user
        config.set_request_property(get_user, 'user', reify=True)
        return config

    def owsproxy_config(self, settings, config):
        protected_path = settings.get('twitcher.ows_proxy_protected_path', '/ows')

        config.add_route('owsproxy', protected_path + '/{service_name}')
        config.add_route('owsproxy_extra', protected_path + '/{service_name}/{extra_path:.*}')
        config.add_route('owsproxy_secured', protected_path + '/{service_name}/{access_token}')

        # include postgresdb
        config.include('magpieadapter.postgresdb')

        config.add_view(owsproxy, route_name='owsproxy')
        config.add_view(owsproxy, route_name='owsproxy_extra')
        config.add_view(owsproxy, route_name='owsproxy_secured')
