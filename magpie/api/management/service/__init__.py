import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding api service ...')
    # Add all the rest api routes
    config.add_route('services', '/services')
    config.add_route('service', '/services/{service_name}')
    config.add_route('services_type', '/services/types/{service_type}')
    config.add_route('service_permissions', '/services/{service_name}/permissions')
    config.add_route('service_resources', '/services/{service_name}/resources')
    config.add_route('service_resource', '/services/{service_name}/resources/{resource_id}')
    config.add_route('service_type_resource_types', '/services/types/{service_type}/resources/types')

    config.scan()
