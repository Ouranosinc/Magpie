import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding login ...')
    config.add_route('login', '/ui/login')
    config.add_route('logout', '/ui/logout')
    config.add_route('register', '/ui/register')

    config.scan()
