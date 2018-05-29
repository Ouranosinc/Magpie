import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding resource ...')
    # Add all the rest api routes
    config.add_route('resources', '/resources')
    config.add_route('resource', '/resources/{resource_id}')
    config.add_route('resource_permissions', '/resources/{resource_id}/permissions')

    config.scan()
