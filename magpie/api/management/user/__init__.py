from api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding api user ...')
    # Add all the rest api routes
    config.add_route(**service_api_route_info(UsersAPI))
    config.add_route(**service_api_route_info(UserAPI))
    config.add_route(**service_api_route_info(UserGroupsAPI))
    config.add_route(**service_api_route_info(UserGroupAPI))
    config.add_route(**service_api_route_info(UserServicesAPI))
    config.add_route(**service_api_route_info(UserInheritedServicesAPI))
    config.add_route(**service_api_route_info(UserServicePermissionsAPI))
    config.add_route(**service_api_route_info(UserServicePermissionAPI))
    config.add_route(**service_api_route_info(UserServiceInheritedPermissionsAPI))
    config.add_route(**service_api_route_info(UserServiceResourcesAPI))
    config.add_route(**service_api_route_info(UserServiceInheritedResourcesAPI))
    config.add_route(**service_api_route_info(UserResourcesAPI))
    config.add_route(**service_api_route_info(UserInheritedResourcesAPI))
    config.add_route(**service_api_route_info(UserResourceTypesAPI))
    config.add_route(**service_api_route_info(UserResourcePermissionsAPI))
    config.add_route(**service_api_route_info(UserResourcePermissionAPI))
    config.add_route(**service_api_route_info(UserResourceInheritedPermissionsAPI))

    config.scan()
