import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding user ...')
    # Add all the rest api routes
    config.add_route('users', '/users')
    config.add_route('user', '/users/{user_name}')
    config.add_route('user_groups', 'users/{user_name}/groups')
    config.add_route('user_group', '/users/{user_name}/groups/{group_name}')
    config.add_route('user_services', '/users/{user_name}/services')
    config.add_route('user_inherited_services', '/users/{user_name}/inherited_services')
    config.add_route('user_service_permissions', '/users/{user_name}/services/{service_name}/permissions')
    config.add_route('user_service_permission', '/users/{user_name}/services/{service_name}/permissions/{permission_name}')
    #config.add_route('user_service_resources', '/users/{user_name}/services/{service_name}/resources')
    config.add_route('user_service_inherited_permissions', '/users/{user_name}/services/{service_name}/inherited_permissions')

    config.add_route('user_resources', '/users/{user_name}/resources')
    config.add_route('user_inherited_resources', '/users/{user_name}/inherited_resources')
    config.add_route('user_resources_type', '/users/{user_name}/resources/types/{resource_type}')
    config.add_route('user_resource_permissions', '/users/{user_name}/resources/{resource_id}/permissions')
    config.add_route('user_resource_permission', '/users/{user_name}/resources/{resource_id}/permissions/{permission_name}')
    config.add_route('user_resource_inherited_permissions', '/users/{user_name}/resource/{resource_id}/inherited_permissions')

    config.scan()
