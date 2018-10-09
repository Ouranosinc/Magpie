from magpie.api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api login ...')
    # Add all the rest api routes
    config.add_route(**service_api_route_info(SessionAPI))
    #config.add_route('signin_internal', '/signin_internal') # added via 'magpie.ini' configs
    config.add_route('signin_external', '/signin_external')
    config.add_route('signin', '/signin')
    #config.add_route('signout', '/signout')
    config.add_route(**service_api_route_info(ProvidersAPI))
    config.add_route(**service_api_route_info(ProviderSigninAPI))
    config.scan()
