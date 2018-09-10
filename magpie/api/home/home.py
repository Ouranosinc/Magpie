from magpie.definitions.pyramid_definitions import *
from magpie.api.api_rest_schemas import *
from magpie.api.api_except import *
from magpie import db, __meta__


#@view_config(route_name='home', renderer='templates/home.pt')
#def home_config_view(request):
#    return dict()


@VersionAPI.get(tags=[APITag], api_security=SecurityEveryoneAPI, response_schemas=Version_GET_responses)
@view_config(route_name=VersionAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_version(request):
    """
    Version information of the API.
    """
    return valid_http(httpSuccess=HTTPOk,
                      content={u'version': __meta__.__version__, u'db_version': db.get_database_revision(request.db)},
                      detail=Version_GET_OkResponseSchema.description, contentType='application/json')
