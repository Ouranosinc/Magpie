from magpie.api import schemas as s
from magpie.definitions.pyramid_definitions import NO_PERMISSION_REQUIRED
from api.swagger.views import api_swagger
from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding swagger...")
    config.add_route(**s.service_api_route_info(s.SwaggerAPI))
    config.add_route(**s.service_api_route_info(s.SwaggerGenerator))
    config.add_view(s.api_schema, route_name=s.SwaggerGenerator.name, request_method="GET",
                    renderer="json", permission=NO_PERMISSION_REQUIRED)
    config.add_view(api_swagger, route_name=s.SwaggerAPI.name,
                    renderer="templates/swagger_ui.mako", permission=NO_PERMISSION_REQUIRED)
