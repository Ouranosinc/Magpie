import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding home ...')
    config.add_route('home', '/')
    config.add_route('test', '/test')

    config.scan()
