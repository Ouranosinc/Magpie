from magpie.api import api_except as ax, api_rest_schemas as s
from magpie.definitions.pyramid_definitions import NO_PERMISSION_REQUIRED, HTTPOk, view_config
from magpie.db import get_database_revision
from magpie.utils import CONTENT_TYPE_JSON
from magpie import __meta__


@s.VersionAPI.get(tags=[s.APITag], api_security=s.SecurityEveryoneAPI, response_schemas=s.Version_GET_responses)
@view_config(route_name=s.VersionAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_version(request):
    """
    Version information of the API.
    """
    version_db = None
    # noinspection PyBroadException
    try:
        version_db = get_database_revision(request.db)
    except Exception:
        pass
    version = {
        u"version": __meta__.__version__,
        u"db_version": version_db
    }
    return ax.valid_http(httpSuccess=HTTPOk, content=version, contentType=CONTENT_TYPE_JSON,
                         detail=s.Version_GET_OkResponseSchema.description)
