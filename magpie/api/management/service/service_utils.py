from typing import TYPE_CHECKING

import six
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPUnprocessableEntity
)
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService

from magpie import models
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.management.group.group_utils import create_group_resource_permission_response
from magpie.api.management.service.service_formats import format_service
from magpie.constants import get_constant
from magpie.permissions import Permission
from magpie.register import SERVICES_PHOENIX_ALLOWED, sync_services_phoenix
from magpie.services import SERVICE_TYPE_DICT
from magpie.utils import get_logger

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Iterable, Optional

    from pyramid.httpexceptions import HTTPException
    from sqlalchemy.orm.session import Session

    from magpie.typedefs import JSON, Str

LOGGER = get_logger(__name__)


def create_service(service_name, service_type, service_url, service_push, service_config, db_session):
    # type: (Str, Str, Str, bool, Optional[JSON], Session) -> HTTPException
    """
    Generates an instance to register a new service.
    """

    def _add_service_magpie_and_phoenix(svc, svc_push, db):
        db.add(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db.query(models.Service))

        # sometimes, resource ID is not updated, fetch the service to obtain it
        if not svc.resource_id:
            svc = ax.evaluate_call(lambda: models.Service.by_service_name(service_name, db_session=db_session),
                                   fallback=lambda: db_session.rollback(), http_error=HTTPInternalServerError,
                                   msg_on_fail=s.Services_POST_InternalServerErrorResponseSchema.description,
                                   content={"service_name": str(service_name), "resource_id": svc.resource_id})
            ax.verify_param(svc.resource_id, not_none=True, param_compare=int, is_type=True,
                            http_error=HTTPInternalServerError,
                            msg_on_fail=s.Services_POST_InternalServerErrorResponseSchema.description,
                            content={"service_name": str(service_name), "resource_id": svc.resource_id},
                            param_name="service_name")
        return svc

    ax.verify_param(service_type, not_none=True, not_empty=True, is_type=True,
                    param_name="service_type", param_compare=six.string_types,
                    http_error=HTTPBadRequest, msg_on_fail=s.Services_POST_BadRequestResponseSchema.description)
    ax.verify_param(service_type, is_in=True, param_compare=SERVICE_TYPE_DICT.keys(), param_name="service_type",
                    http_error=HTTPBadRequest, msg_on_fail=s.Services_POST_BadRequestResponseSchema.description)
    ax.verify_param(service_url, matches=True, param_compare=ax.URL_REGEX, param_name="service_url",
                    http_error=HTTPBadRequest, msg_on_fail=s.Services_POST_Params_BadRequestResponseSchema.description)
    ax.verify_param(service_name, not_empty=True, not_none=True, matches=True,
                    param_name="service_name", param_compare=ax.PARAM_REGEX,
                    http_error=HTTPBadRequest, msg_on_fail=s.Services_POST_Params_BadRequestResponseSchema.description)
    ax.verify_param(models.Service.by_service_name(service_name, db_session=db_session), is_none=True,
                    param_name="service_name", with_param=False, content={"service_name": str(service_name)},
                    http_error=HTTPConflict, msg_on_fail=s.Services_POST_ConflictResponseSchema.description)
    if service_config is not None:
        ax.verify_param(service_config, param_name="configuration", param_compare=dict, is_type=True,
                        http_error=HTTPUnprocessableEntity,
                        msg_on_fail=s.Service_CheckConfig_UnprocessableEntityResponseSchema.description)
    service = ax.evaluate_call(lambda: models.Service(resource_name=str(service_name),
                                                      resource_type=models.Service.resource_type_name,
                                                      configuration=service_config,
                                                      url=str(service_url), type=str(service_type)),  # noqa
                               fallback=lambda: db_session.rollback(), http_error=HTTPForbidden,
                               msg_on_fail=s.Services_POST_UnprocessableEntityResponseSchema.description,
                               content={"service_name": str(service_name),
                                        "resource_type": models.Service.resource_type_name,
                                        "service_url": str(service_url), "service_type": str(service_type)})

    service = ax.evaluate_call(lambda: _add_service_magpie_and_phoenix(service, service_push, db_session),
                               fallback=lambda: db_session.rollback(), http_error=HTTPForbidden,
                               msg_on_fail=s.Services_POST_ForbiddenResponseSchema.description,
                               content=format_service(service, show_private_url=True))
    return ax.valid_http(http_success=HTTPCreated, detail=s.Services_POST_CreatedResponseSchema.description,
                         content={"service": format_service(service, show_private_url=True)})


def get_services_by_type(service_type, db_session):
    # type: (Str, Session) -> Iterable[models.Service]
    """
    Obtains all services that correspond to requested service-type.
    """
    ax.verify_param(service_type, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                    msg_on_fail="Invalid 'service_type' value '" + str(service_type) + "' specified")
    services = db_session.query(models.Service).filter(models.Service.type == service_type)
    return sorted(services, key=lambda svc: svc.resource_name)


def add_service_getcapabilities_perms(service, db_session, group_name=None):
    if service.type in SERVICES_PHOENIX_ALLOWED and \
            Permission.GET_CAPABILITIES in SERVICE_TYPE_DICT[service.type].permissions:
        if group_name is None:
            group_name = get_constant("MAGPIE_ANONYMOUS_USER")
        group = GroupService.by_group_name(group_name, db_session=db_session)
        perm = ResourceService.perm_by_group_and_perm_name(service.resource_id, group.id,
                                                           Permission.GET_CAPABILITIES.value, db_session)
        if perm is None:  # not set, create it
            create_group_resource_permission_response(group, service, Permission.GET_CAPABILITIES, db_session)
