import logging
logger = logging.getLogger(__name__)


def includeme(config):
    settings = config.registry.settings

    logger.info('Adding api home ...')
    #config.add_route('home', '/')
    config.scan()
