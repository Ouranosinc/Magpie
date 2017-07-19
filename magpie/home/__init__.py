import logging
logger = logging.getLogger(__name__)



def includeme(config):
    settings = config.registry.settings

    logger.info('Adding config ...')
    config.add_route('home', '/')
    config.scan()
