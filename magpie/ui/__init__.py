import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding ui routes ...')

    # Add all the admin ui routes
    config.include('ui.login')
    config.include('ui.home')
    config.include('ui.management')
