from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.api import schemas as s
    LOGGER.info("Adding API network ...")
    config.add_route(**s.service_api_route_info(s.NetworkTokenAPI))  # /network/token POST and DELETE
    config.add_route(**s.service_api_route_info(s.NetworkJSONWebKeySetAPI))  # /network/jwks GET
    config.include("magpie.api.management.network.node")
    config.include("magpie.api.management.network.remote_user")
    config.scan()
