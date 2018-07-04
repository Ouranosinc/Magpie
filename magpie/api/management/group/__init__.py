from api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api group ...')
    # Add all the rest api routes
    config.add_route(**service_api_route_info(GroupsAPI))
    config.add_route(**service_api_route_info(GroupAPI))
    config.add_route(**service_api_route_info(GroupUsersAPI))
    config.add_route(**service_api_route_info(GroupServicesAPI))
    config.add_route(**service_api_route_info(GroupServicePermissionsAPI))
    config.add_route(**service_api_route_info(GroupServicePermissionAPI))
    config.add_route(**service_api_route_info(GroupServiceResourcesAPI))
    config.add_route(**service_api_route_info(GroupResourcesAPI))
    config.add_route(**service_api_route_info(GroupResourcePermissionsAPI))
    config.add_route(**service_api_route_info(GroupResourcePermissionAPI))
    config.add_route(**service_api_route_info(GroupResourceTypesAPI))

    config.scan()
