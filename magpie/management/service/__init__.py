import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding service ...')
    # Add all the rest api routes
    config.add_route('services', '/services')
    config.add_route('service', '/services/{service_name}')

    config.scan()
