from magpie.constants import get_constant
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.api import schemas as s
    LOGGER.info("Adding API login...")
    # Add all the rest api routes
    config.add_route(**s.service_api_route_info(s.SessionAPI))
    config.add_route(**s.service_api_route_info(s.SigninAPI))
    config.add_route(**s.service_api_route_info(s.ProvidersAPI))
    config.add_route(**s.service_api_route_info(s.ProviderSigninAPI))
    if get_constant("MAGPIE_NETWORK_ENABLED", config, settings_name="magpie.network_enabled"):
        config.add_route(**s.service_api_route_info(s.TokenAPI))
        config.add_route(**s.service_api_route_info(s.TokenValidateAPI))
    config.scan()
