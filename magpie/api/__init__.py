import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api routes ...')

    # Add all the admin ui routes
    config.include('magpie.api.esgf')
    config.include('magpie.api.home')
    config.include('magpie.api.login')
    config.include('magpie.api.management')
    config.scan()
