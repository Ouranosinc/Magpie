from api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding api resource ...')
    # Add all the rest api routes
    config.add_route(**service_api_route_info(ResourcesAPI))
    config.add_route(**service_api_route_info(ResourceAPI))
    config.add_route(**service_api_route_info(ResourcePermissionsAPI))

    config.scan()
