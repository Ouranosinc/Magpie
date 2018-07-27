from magpie.api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding swagger ...')
    config.add_route(**service_api_route_info(SwaggerAPI))
    config.add_route(SwaggerAPI_extra_name, SwaggerAPI_extra_path)
    config.scan()
