from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from pyramid.exceptions import ConfigurationError

    from magpie import utils
    from magpie.api import schemas as s

    LOGGER.info("Adding API network ...")
    try:
        utils.check_network_configured(config)
    except ConfigurationError as exc:
        LOGGER.error("API network failed with following configuration error: %s", exc)
        raise
    config.add_route(**s.service_api_route_info(s.NetworkTokenAPI))
    config.add_route(**s.service_api_route_info(s.NetworkJSONWebKeySetAPI))
    config.add_route(**s.service_api_route_info(s.NetworkDecodeJWTAPI))
    config.add_route(**s.service_api_route_info(s.NetworkTokensAPI))
    config.include("magpie.api.management.network.node")
    config.include("magpie.api.management.network.remote_user")
    config.scan()
