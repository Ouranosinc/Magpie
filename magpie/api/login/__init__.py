from magpie.api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api login ...')
    # Add all the rest api routes
    config.add_route(**service_api_route_info(SessionAPI))
    config.add_route(**service_api_route_info(SigninAPI))
    #config.add_route('signin_internal', '/signin_internal')    # added via 'magpie.ini' configs as ZigguratSignin
    config.add_route('signin_external', '/signin_external')     # for redirect handling, not to be used directly
    #config.add_route('signout', '/signout')                    # added via 'magpie.ini' configs as ZigguratSignout
    config.add_route(**service_api_route_info(ProvidersAPI))
    config.add_route(**service_api_route_info(ProviderSigninAPI))
    config.scan()
