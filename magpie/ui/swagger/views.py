from magpie.api.api_rest_schemas import *
from magpie.constants import MAGPIE_MODULE_DIR
import os


@SwaggerAPI.get(tags=[APITag])
#@view_config(route_name=SwaggerAPI.name, renderer='templates/swagger_ui.mako', permission=NO_PERMISSION_REQUIRED)
#@view_config(route_name=SwaggerAPI_extra_name, renderer='templates/swagger_ui.mako', permission=NO_PERMISSION_REQUIRED)
def api_swagger(request):
    """
    Swagger UI route to display the Magpie REST API schemas.
    """
    swagger_versions_dir = '{}'.format(os.path.abspath(os.path.join(MAGPIE_MODULE_DIR, 'ui/swagger/versions')))
    swagger_ui_path = SwaggerGenerator.path
    # come back one level if path ends with '/' to properly find json
    if request.url.endswith(SwaggerAPI.path + '/'):
        swagger_ui_path = '../{}'.format(swagger_ui_path.lstrip('/'))
    return_data = {'api_title': TitleAPI,
                   'api_schema_path': swagger_ui_path,
                   'api_schema_versions_dir': swagger_versions_dir}
    return return_data
