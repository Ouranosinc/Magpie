from magpie.utils import get_logger
logger = get_logger(__name__)


def includeme(config):
    logger.info('Adding api routes ...')

    # Add all the admin ui routes
    config.include('magpie.api.home')
    config.include('magpie.api.login')
    config.include('magpie.api.management')
