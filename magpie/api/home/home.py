from magpie.api import exception as ax, schemas as s
from magpie.definitions.pyramid_definitions import NO_PERMISSION_REQUIRED, HTTPOk, view_config
from magpie.db import get_database_revision
from magpie.utils import print_log, get_logger, get_magpie_url, CONTENT_TYPE_JSON
from magpie import __meta__
from copy import deepcopy

import logging
LOGGER = get_logger(__name__)


# noinspection PyUnusedLocal
@s.HomepageAPI.get(tags=[s.APITag], api_security=s.SecurityEveryoneAPI, response_schemas=s.Homepage_GET_responses)
def get_homepage(request):
    """
    Magpie API homepage (only if Magpie UI is not enabled).
    """
    body = deepcopy(s.InfoAPI)
    body.update({
        u"title": s.TitleAPI,
        u"name": __meta__.__package__,
        u"documentation": get_magpie_url() + s.SwaggerAPI.path
    })
    return ax.valid_http(httpSuccess=HTTPOk, content=body, contentType=CONTENT_TYPE_JSON,
                         detail=s.Version_GET_OkResponseSchema.description)


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
    except Exception as ex:
        print_log("Failed to retrieve database revision: [{!r}]".format(ex), LOGGER, logging.WARNING)
    version = {
        u"version": __meta__.__version__,
        u"db_version": version_db
    }
    return ax.valid_http(httpSuccess=HTTPOk, content=version, contentType=CONTENT_TYPE_JSON,
                         detail=s.Version_GET_OkResponseSchema.description)
