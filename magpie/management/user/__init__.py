import logging
logger = logging.getLogger(__name__)


def includeme(config):
    settings = config.registry.settings

    logger.info('Adding user ...')
    # Add all the rest api routes
    config.add_route('get_user', '/users/{user_name}')

    config.scan()
