from magpie.api import schemas as s
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding api group...")
    # Add all the rest api routes
    config.add_route(**s.service_api_route_info(s.GroupsAPI))
    config.add_route(**s.service_api_route_info(s.GroupAPI))
    config.add_route(**s.service_api_route_info(s.GroupUsersAPI))
    config.add_route(**s.service_api_route_info(s.GroupServicesAPI))
    config.add_route(**s.service_api_route_info(s.GroupServicePermissionsAPI))
    config.add_route(**s.service_api_route_info(s.GroupServicePermissionAPI))
    config.add_route(**s.service_api_route_info(s.GroupServiceResourcesAPI))
    config.add_route(**s.service_api_route_info(s.GroupResourcesAPI))
    config.add_route(**s.service_api_route_info(s.GroupResourcePermissionsAPI))
    config.add_route(**s.service_api_route_info(s.GroupResourcePermissionAPI))

    config.scan()
