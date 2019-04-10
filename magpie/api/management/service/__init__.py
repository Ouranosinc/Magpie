from magpie.api import schemas as s
from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info('Adding api service...')
    # NOTE:
    #   routes 'by type' must be before 'by name' to be evaluated first
    #   order is important to preserve expected behaviour,
    #   otherwise service named 'types' is searched before
    # --- service by type ---
    config.add_route(**s.service_api_route_info(s.ServiceTypesAPI))
    config.add_route(**s.service_api_route_info(s.ServiceTypeAPI))
    config.add_route(**s.service_api_route_info(s.ServiceTypeResourcesAPI))
    config.add_route(**s.service_api_route_info(s.ServiceTypeResourceTypesAPI))
    # --- service by name ---
    config.add_route(**s.service_api_route_info(s.ServicesAPI))
    config.add_route(**s.service_api_route_info(s.ServiceAPI))
    config.add_route(**s.service_api_route_info(s.ServicePermissionsAPI))
    config.add_route(**s.service_api_route_info(s.ServiceResourcesAPI))
    config.add_route(**s.service_api_route_info(s.ServiceResourceAPI))
    config.scan()
