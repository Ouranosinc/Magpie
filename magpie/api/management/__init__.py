import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding management routes ...')
    config.include('magpie.api.management.group')
    config.include('magpie.api.management.user')
    config.include('magpie.api.management.service')
    config.include('magpie.api.management.resource')
    config.scan()
