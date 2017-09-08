import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding login ...')
    config.add_route('login', '/login')
    config.add_route('register', '/register')

    config.scan()
