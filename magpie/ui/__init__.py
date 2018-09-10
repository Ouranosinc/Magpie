import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding ui routes ...')

    # Add all the admin ui routes
    config.include('magpie.ui.login')
    config.include('magpie.ui.home')
    config.include('magpie.ui.management')
    config.include('magpie.ui.swagger')
    #config.scan()
