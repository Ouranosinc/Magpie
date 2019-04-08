from magpie.api import api_rest_schemas as s
from magpie.constants import get_constant
import os


# noinspection PyUnusedLocal
@s.SwaggerAPI.get(tags=[s.APITag])
def api_swagger(request):
    """
    Swagger UI route to display the Magpie REST API schemas.
    """
    magpie_root = get_constant('MAGPIE_MODULE_DIR')
    swagger_versions_dir = os.path.abspath(os.path.join(magpie_root, 'ui/swagger/versions'))
    swagger_ui_path = s.SwaggerGenerator.path.lstrip('/')
    return_data = {'api_title': s.TitleAPI,
                   'api_schema_path': swagger_ui_path,
                   'api_schema_versions_dir': swagger_versions_dir}
    return return_data
