from magpie.api import schemas as s
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding API register...")
    config.add_route(**s.service_api_route_info(s.RegisterGroupsAPI))
    config.add_route(**s.service_api_route_info(s.RegisterGroupAPI))
    config.scan()
