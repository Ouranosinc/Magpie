from magpie.api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api home ...')
    #config.add_route('home', '/')
    config.add_route(**service_api_route_info(VersionAPI))
    config.scan()
