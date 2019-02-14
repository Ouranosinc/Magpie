# noinspection PyUnusedLocal
def includeme(config):
    from magpie.common import get_logger
    logger = get_logger(__name__)
    logger.info('Adding definitions...')
