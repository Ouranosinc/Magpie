from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info('Adding management routes ...')
    config.include('magpie.api.management.group')
    config.include('magpie.api.management.user')
    config.include('magpie.api.management.service')
    config.include('magpie.api.management.resource')
    config.scan()
