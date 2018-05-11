import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding group ...')
    # Add all the rest api routes
    config.add_route('groups', '/groups')
    config.add_route('group', '/groups/{group_name}')
    config.add_route('group_users', '/groups/{group_name}/users')
    config.add_route('group_services', '/groups/{group_name}/services')
    config.add_route('group_service_permissions', '/groups/{group_name}/services/{service_name}/permissions')
    config.add_route('group_service_permission', '/groups/{group_name}/services/{service_name}/permissions/{permission_name}')
    config.add_route('group_service_resources', '/groups/{group_name}/services/{service_name}/resources')

    config.add_route('group_resources', '/groups/{group_name}/resources')
    config.add_route('group_resource_permissions', '/groups/{group_name}/resources/{resource_id}/permissions')
    config.add_route('group_resource_permission', '/groups/{group_name}/resources/{resource_id}/permissions/{permission_name}')
    config.add_route('group_resources_type', '/groups/{group_name}/resources/types/{resource_type}')

    config.scan()
