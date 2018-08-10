from magpie.api.api_rest_schemas import *
from magpie.ui.swagger.views import api_swagger
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding swagger ...')
    config.add_route(**service_api_route_info(SwaggerAPI))
    config.add_route(SwaggerAPI_extra_name, SwaggerAPI_extra_path)
    config.add_route(**service_api_route_info(SwaggerGenerator))
    config.add_view(api_schema, route_name=SwaggerGenerator.name, request_method='GET',
                    renderer='json', permission=NO_PERMISSION_REQUIRED)
    config.add_view(api_swagger, route_name=SwaggerAPI.name,
                    renderer='templates/swagger_ui.mako', permission=NO_PERMISSION_REQUIRED)
    config.add_view(api_swagger, route_name=SwaggerAPI_extra_name,
                    renderer='templates/swagger_ui.mako', permission=NO_PERMISSION_REQUIRED)
    # config.scan()
