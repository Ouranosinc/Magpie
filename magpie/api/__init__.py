import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api routes ...')

    # Add all the admin ui routes
    config.include('api.esgf')
    config.include('api.home')
    config.include('api.login')
    config.include('api.management')

    config.add_route('version', '/version')
    config.scan()
