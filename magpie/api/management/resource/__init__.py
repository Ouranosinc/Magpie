from magpie.api import schemas as s
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info('Adding api resource...')
    # Add all the rest api routes
    config.add_route(**s.service_api_route_info(s.ResourcesAPI))
    config.add_route(**s.service_api_route_info(s.ResourceAPI))
    config.add_route(**s.service_api_route_info(s.ResourcePermissionsAPI))

    config.scan()
