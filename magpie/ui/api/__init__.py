import logging
import requests
from definitions.pyramid_definitions import *

logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api-ui ...')
    #config.add_route('api_ui', '/api')
    config.add_route('api_ui', '/magpie/api')
    #config.add_static_view('swagger_ui', 'swagger-ui', cache_max_age=3600)
    config.scan()
