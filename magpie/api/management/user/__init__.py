from magpie.api import schemas as s
from magpie.models import UserFactory
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding API user...")

    # note: routes that require user 'self' operations must add the following, otherwise default RootFactory is used
    user_kwargs = {"factory": UserFactory, "traverse": "/{user_name}"}

    # Add user variable routes
    config.add_route(**s.service_api_route_info(s.UsersAPI))  # no user instance, admin-only
    config.add_route(**s.service_api_route_info(s.UserAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserGroupsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserGroupAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserServicesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserInheritedServicesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserServicePermissionsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserServicePermissionAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserServiceInheritedPermissionsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserServiceResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserServiceInheritedResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserInheritedResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserResourceTypesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserResourcePermissionsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserResourcePermissionAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.UserResourceInheritedPermissionsAPI, **user_kwargs))
    # Logged User routes
    config.add_route(**s.service_api_route_info(s.LoggedUserAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserGroupsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserGroupAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserServicesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserInheritedServicesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserServicePermissionsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserServicePermissionAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserServiceInheritedPermissionsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserServiceResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserServiceInheritedResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserInheritedResourcesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourceTypesAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourcePermissionsAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourcePermissionAPI, **user_kwargs))
    config.add_route(**s.service_api_route_info(s.LoggedUserResourceInheritedPermissionsAPI, **user_kwargs))

    config.scan()
