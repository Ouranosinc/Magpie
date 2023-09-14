from magpie.api import schemas as s
from magpie.constants import get_constant
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    if get_constant("MAGPIE_NETWORK_MODE", settings_name="magpie.network_mode"):
        LOGGER.info("Adding API network node...")
        config.add_route(**s.service_api_route_info(s.NetworkNodeAPI))
        config.add_route(**s.service_api_route_info(s.NetworkNodesAPI))
        config.scan()
