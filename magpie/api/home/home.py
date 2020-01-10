import logging
from copy import deepcopy

from pyramid.httpexceptions import HTTPOk
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.view import view_config

from magpie import __meta__
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.db import get_database_revision
from magpie.utils import CONTENT_TYPE_JSON, get_logger, get_magpie_url, print_log

LOGGER = get_logger(__name__)


@s.HomepageAPI.get(tags=[s.APITag], api_security=s.SecurityEveryoneAPI, response_schemas=s.Homepage_GET_responses)
def get_homepage(request):  # noqa: W0212
    """
    Magpie API homepage (only if Magpie UI is not enabled).
    """
    body = deepcopy(s.InfoAPI)
    body.update({
        u"title": s.TitleAPI,
        u"name": __meta__.__package__,
        u"documentation": get_magpie_url() + s.SwaggerAPI.path
    })
    return ax.valid_http(http_success=HTTPOk, content=body, content_type=CONTENT_TYPE_JSON,
                         detail=s.Version_GET_OkResponseSchema.description)


@s.VersionAPI.get(tags=[s.APITag], api_security=s.SecurityEveryoneAPI, response_schemas=s.Version_GET_responses)
@view_config(route_name=s.VersionAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_version(request):
    """
    Version information of the API.
    """
    version_db = None
    try:
        version_db = get_database_revision(request.db)
    except Exception as exc:
        print_log("Failed to retrieve database revision: [{!r}]".format(exc), LOGGER, logging.WARNING)
    version = {
        u"version": __meta__.__version__,
        u"db_version": version_db
    }
    return ax.valid_http(http_success=HTTPOk, content=version, content_type=CONTENT_TYPE_JSON,
                         detail=s.Version_GET_OkResponseSchema.description)
