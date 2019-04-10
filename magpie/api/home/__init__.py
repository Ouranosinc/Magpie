from magpie.api import schemas as s
from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding api home...")
    # config.add_route("home", "/")
    config.add_route(**s.service_api_route_info(s.VersionAPI))
    config.scan()
