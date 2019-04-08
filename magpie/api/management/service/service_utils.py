from magpie.api import api_except as ax, api_rest_schemas as s
from magpie.api.management.group.group_utils import create_group_resource_permission
from magpie.api.management.service.service_formats import format_service
from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import (
    HTTPCreated,
    HTTPForbidden,
    HTTPNotAcceptable,
    HTTPInternalServerError,
)
from magpie.definitions.ziggurat_definitions import GroupService, ResourceService
from magpie.register import sync_services_phoenix, SERVICES_PHOENIX_ALLOWED
from magpie.services import SERVICE_TYPE_DICT
from magpie.utils import get_logger
from magpie import models
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Str  # noqa: F401
    from magpie.definitions.sqlalchemy_definitions import Session  # noqa: F401
    from magpie.definitions.pyramid_definitions import HTTPException  # noqa: F401
LOGGER = get_logger(__name__)


def create_service(service_name, service_type, service_url, service_push, db_session):
    # type: (Str, Str, Str, bool, Session) -> HTTPException
    """Generates an instance to register a new service."""

    def _add_service_magpie_and_phoenix(svc, svc_push, db):
        db.add(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db.query(models.Service))

        # sometimes, resource ID is not updated, fetch the service to obtain it
        if not svc.resource_id:
            svc = ax.evaluate_call(lambda: models.Service.by_service_name(service_name, db_session=db_session),
                                   fallback=lambda: db_session.rollback(), httpError=HTTPInternalServerError,
                                   msgOnFail=s.Services_POST_InternalServerErrorResponseSchema.description,
                                   content={u'service_name': str(service_name), u'resource_id': svc.resource_id})
            ax.verify_param(svc.resource_id, notNone=True, paramCompare=int, ofType=True,
                            httpError=HTTPInternalServerError,
                            msgOnFail=s.Services_POST_InternalServerErrorResponseSchema.description,
                            content={u'service_name': str(service_name), u'resource_id': svc.resource_id},
                            paramName=u'service_name')
        return svc

    # noinspection PyArgumentList
    service = ax.evaluate_call(lambda: models.Service(resource_name=str(service_name),
                                                      resource_type=models.Service.resource_type_name,
                                                      url=str(service_url), type=str(service_type)),
                               fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
                               msgOnFail=s.Services_POST_UnprocessableEntityResponseSchema.description,
                               content={u'service_name': str(service_name),
                                        u'resource_type': models.Service.resource_type_name,
                                        u'service_url': str(service_url), u'service_type': str(service_type)})

    service = ax.evaluate_call(lambda: _add_service_magpie_and_phoenix(service, service_push, db_session),
                               fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
                               msgOnFail=s.Services_POST_ForbiddenResponseSchema.description,
                               content=format_service(service, show_private_url=True))
    return ax.valid_http(httpSuccess=HTTPCreated, detail=s.Services_POST_CreatedResponseSchema.description,
                         content={u'service': format_service(service, show_private_url=True)})


def get_services_by_type(service_type, db_session):
    ax.verify_param(service_type, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                    msgOnFail="Invalid `service_type` value '" + str(service_type) + "' specified")
    services = db_session.query(models.Service).filter(models.Service.type == service_type)
    return sorted(services, key=lambda svc: svc.resource_name)


def add_service_getcapabilities_perms(service, db_session, group_name=None):
    if service.type in SERVICES_PHOENIX_ALLOWED \
    and 'getcapabilities' in SERVICE_TYPE_DICT[service.type].permission_names:  # noqa: F401
        if group_name is None:
            group_name = get_constant('MAGPIE_ANONYMOUS_USER')
        group = GroupService.by_group_name(group_name, db_session=db_session)
        perm = ResourceService.perm_by_group_and_perm_name(service.resource_id, group.id,
                                                           u'getcapabilities', db_session)
        if perm is None:  # not set, create it
            create_group_resource_permission(u'getcapabilities', service, group, db_session)
