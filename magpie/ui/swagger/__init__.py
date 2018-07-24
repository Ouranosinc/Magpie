from magpie.api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    if config.registry.settings.get('magpie.api_generation_disabled'):
        logger.warn('Skipping swagger ...')
    else:
        logger.info('Adding swagger ...')
        config.add_route(**service_api_route_info(SwaggerAPI))
        config.scan()
