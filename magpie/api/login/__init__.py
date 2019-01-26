from magpie.api import api_rest_schemas as s
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api login ...')
    # Add all the rest api routes
    config.add_route(**s.service_api_route_info(s.SessionAPI))
    config.add_route(**s.service_api_route_info(s.SigninAPI))
    config.add_route(**s.service_api_route_info(s.ProvidersAPI))
    config.add_route(**s.service_api_route_info(s.ProviderSigninAPI))
    config.scan()
