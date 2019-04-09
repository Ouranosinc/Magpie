from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.api import api_rest_schemas as s
    LOGGER.info("Adding api login...")
    # Add all the rest api routes
    config.add_route(**s.service_api_route_info(s.SessionAPI))
    config.add_route(**s.service_api_route_info(s.SigninAPI))
    config.add_route(**s.service_api_route_info(s.ProvidersAPI))
    config.add_route(**s.service_api_route_info(s.ProviderSigninAPI))
    config.scan()
