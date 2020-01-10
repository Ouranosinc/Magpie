import os

from magpie.api import schemas as s
from magpie.constants import MAGPIE_MODULE_DIR


@s.SwaggerAPI.get(tags=[s.APITag], response_schemas=s.SwaggerAPI_GET_responses)
def api_swagger(request):   # noqa: F811
    """
    Swagger UI route to display the Magpie REST API schemas.
    """
    swagger_versions_dir = "{}".format(os.path.abspath(os.path.join(MAGPIE_MODULE_DIR, "ui/swagger/versions")))
    swagger_ui_path = s.SwaggerGenerator.path.lstrip("/")
    return_data = {"api_title": s.TitleAPI,
                   "api_schema_path": swagger_ui_path,
                   "api_schema_versions_dir": swagger_versions_dir}
    return return_data
