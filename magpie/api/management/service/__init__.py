from magpie.api.api_rest_schemas import *
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api service ...')
    # NOTE:
    #   routes 'by type' must be before 'by name' to be evaluated first
    #   order is important to preserve expected behaviour,
    #   otherwise service named 'types' is searched before
    # --- service by type ---
    config.add_route(**service_api_route_info(ServiceTypesAPI))
    config.add_route(**service_api_route_info(ServiceTypeAPI))
    config.add_route(**service_api_route_info(ServiceTypeResourcesAPI))
    config.add_route(**service_api_route_info(ServiceTypeResourceTypesAPI))
    # --- service by name ---
    config.add_route(**service_api_route_info(ServicesAPI))
    config.add_route(**service_api_route_info(ServiceAPI))
    config.add_route(**service_api_route_info(ServicePermissionsAPI))
    config.add_route(**service_api_route_info(ServiceResourcesAPI))
    config.add_route(**service_api_route_info(ServiceResourceAPI))
    config.scan()
