from magpie.api import api_rest_schemas as s
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api home ...')
    # config.add_route('home', '/')
    config.add_route(**s.service_api_route_info(s.VersionAPI))
    config.scan()
