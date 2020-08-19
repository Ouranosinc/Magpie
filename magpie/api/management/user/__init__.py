from magpie.api import schemas as s
from magpie.models import UserFactory
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding API user...")
    # Add all the rest api routes
    config.add_route(**s.service_api_route_info(s.UsersAPI))
    config.add_route(**s.service_api_route_info(s.UserAPI))
    config.add_route(**s.service_api_route_info(s.UserGroupsAPI))
    config.add_route(**s.service_api_route_info(s.UserGroupAPI))
    config.add_route(**s.service_api_route_info(s.UserServicesAPI))
    config.add_route(**s.service_api_route_info(s.UserInheritedServicesAPI))
    config.add_route(**s.service_api_route_info(s.UserServicePermissionsAPI))
    config.add_route(**s.service_api_route_info(s.UserServicePermissionAPI))
    config.add_route(**s.service_api_route_info(s.UserServiceInheritedPermissionsAPI))
    config.add_route(**s.service_api_route_info(s.UserServiceResourcesAPI))
    config.add_route(**s.service_api_route_info(s.UserServiceInheritedResourcesAPI))
    config.add_route(**s.service_api_route_info(s.UserResourcesAPI))
    config.add_route(**s.service_api_route_info(s.UserInheritedResourcesAPI))
    config.add_route(**s.service_api_route_info(s.UserResourceTypesAPI))
    config.add_route(**s.service_api_route_info(s.UserResourcePermissionsAPI))
    config.add_route(**s.service_api_route_info(s.UserResourcePermissionAPI))
    config.add_route(**s.service_api_route_info(s.UserResourceInheritedPermissionsAPI))
    # Logged User routes
    config.add_route(**s.service_api_route_info(s.LoggedUserAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserGroupsAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserGroupAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserServicesAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserInheritedServicesAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserServicePermissionsAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserServicePermissionAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserServiceInheritedPermissionsAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserServiceResourcesAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserServiceInheritedResourcesAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourcesAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserInheritedResourcesAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourceTypesAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourcePermissionsAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourcePermissionAPI))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourceInheritedPermissionsAPI))

    config.scan()
