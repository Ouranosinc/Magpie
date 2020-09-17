from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict, HTTPForbidden, HTTPNotFound, HTTPOk
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.resource import resource_utils as ru
from magpie.api.management.service import service_formats as sf
from magpie.api.management.service import service_utils as su
from magpie.permissions import Permission, format_permissions
from magpie.register import SERVICES_PHOENIX_ALLOWED, sync_services_phoenix
from magpie.services import SERVICE_TYPE_DICT
from magpie.utils import CONTENT_TYPE_JSON

if TYPE_CHECKING:
    from typing import List, Union

    from magpie.typedefs import JSON


@s.ServiceTypesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceTypes_GET_responses)
@view_config(route_name=s.ServiceTypesAPI.name, request_method="GET")
def get_service_types_view(request):  # noqa: F811
    """
    List all available service types.
    """
    return ax.valid_http(http_success=HTTPOk, content={"service_types": list(sorted(SERVICE_TYPE_DICT.keys()))},
                         detail=s.ServiceTypes_GET_OkResponseSchema.description)


@s.ServiceTypeAPI.get(schema=s.ServiceTypes_GET_RequestSchema(), tags=[s.ServicesTag],
                      response_schemas=s.ServiceType_GET_responses)
@view_config(route_name=s.ServiceTypeAPI.name, request_method="GET")
def get_services_by_type_view(request):
    """
    List all registered services from a specific type.
    """
    return get_services_runner(request)


@s.ServicesAPI.get(schema=s.Services_GET_RequestSchema(), tags=[s.ServicesTag],
                   response_schemas=s.Services_GET_responses)
@view_config(route_name=s.ServicesAPI.name, request_method="GET")
def get_services_view(request):
    """
    List all registered services.
    """
    return get_services_runner(request)


def get_services_runner(request):
    """
    Generates services response format from request conditions.

    Obtains the full or filtered list of services categorized by type, or listed as flat list according to request path
    and query parameters.
    """
    service_type_filter = request.matchdict.get("service_type")  # no check because None/empty is for 'all services'
    services_as_list = asbool(ar.get_query_param(request, "flatten", False))

    if not service_type_filter:
        service_types = SERVICE_TYPE_DICT.keys()
    else:
        ax.verify_param(service_type_filter, param_compare=SERVICE_TYPE_DICT.keys(), is_in=True,
                        http_error=HTTPBadRequest, msg_on_fail=s.Services_GET_BadRequestResponseSchema.description,
                        content={"service_type": str(service_type_filter)}, content_type=CONTENT_TYPE_JSON)
        service_types = [service_type_filter]

    svc_content = [] if services_as_list else {}  # type: Union[List[JSON], JSON]
    for service_type in service_types:
        services = su.get_services_by_type(service_type, db_session=request.db)
        if not services_as_list:
            svc_content[service_type] = {}
        for service in services:
            svc_fmt = sf.format_service(service, show_private_url=True)
            if services_as_list:
                svc_content.append(svc_fmt)  # pylint: disable=E1101
            else:
                svc_content[service_type][service.resource_name] = svc_fmt

    return ax.valid_http(http_success=HTTPOk, content={"services": svc_content},
                         detail=s.Services_GET_OkResponseSchema.description)


@s.ServicesAPI.post(schema=s.Services_POST_RequestBodySchema(), tags=[s.ServicesTag],
                    response_schemas=s.Services_POST_responses)
@view_config(route_name=s.ServicesAPI.name, request_method="POST")
def register_service_view(request):
    """
    Registers a new service.
    """
    # accomplish basic validations here, create_service will do more field-specific checks
    service_name = ar.get_value_multiformat_body_checked(request, "service_name")
    service_url = ar.get_value_multiformat_body_checked(request, "service_url", pattern=ax.PARAM_REGEX)
    service_type = ar.get_value_multiformat_body_checked(request, "service_type")
    service_push = asbool(ar.get_multiformat_body(request, "service_push", default=False))
    return su.create_service(service_name, service_type, service_url, service_push, db_session=request.db)


@s.ServiceAPI.patch(schema=s.Service_PATCH_RequestBodySchema(), tags=[s.ServicesTag],
                    response_schemas=s.Service_PATCH_responses)
@view_config(route_name=s.ServiceAPI.name, request_method="PATCH")
def update_service_view(request):
    """
    Update service information.
    """
    service = ar.get_service_matchdict_checked(request)
    service_push = asbool(ar.get_multiformat_body(request, "service_push", default=False))

    def select_update(new_value, old_value):
        return new_value if new_value is not None and not new_value == "" else old_value

    # None/Empty values are accepted in case of unspecified
    svc_name = select_update(ar.get_multiformat_body(request, "service_name"), service.resource_name)
    svc_url = select_update(ar.get_multiformat_body(request, "service_url"), service.url)
    ax.verify_param(svc_name, param_compare="types", not_equal=True,
                    param_name="service_name", http_error=HTTPForbidden,
                    msg_on_fail=s.Service_PATCH_ForbiddenResponseSchema_ReservedKeyword.description)
    ax.verify_param(svc_name == service.resource_name and svc_url == service.url, not_equal=True,
                    param_compare=True, param_name="service_name/service_url",
                    http_error=HTTPBadRequest, msg_on_fail=s.Service_PATCH_BadRequestResponseSchema.description)

    if svc_name != service.resource_name:
        all_services = request.db.query(models.Service)
        all_svc_names = [svc.resource_name for svc in all_services]
        ax.verify_param(svc_name, not_in=True, param_compare=all_svc_names, with_param=False,
                        http_error=HTTPConflict, content={"service_name": str(svc_name)},
                        msg_on_fail=s.Service_PATCH_ConflictResponseSchema.description)

    def update_service_magpie_and_phoenix(_svc, new_name, new_url, svc_push, db_session):
        _svc.resource_name = new_name
        _svc.url = new_url
        has_getcap = Permission.GET_CAPABILITIES in SERVICE_TYPE_DICT[_svc.type].permissions
        if svc_push and _svc.type in SERVICES_PHOENIX_ALLOWED and has_getcap:
            # (re)apply getcapabilities to updated service to ensure updated push
            su.add_service_getcapabilities_perms(_svc, db_session)
            sync_services_phoenix(db_session.query(models.Service))  # push all services

    old_svc_content = sf.format_service(service, show_private_url=True)
    err_svc_content = {"service": old_svc_content, "new_service_name": svc_name, "new_service_url": svc_url}
    ax.evaluate_call(lambda: update_service_magpie_and_phoenix(service, svc_name, svc_url, service_push, request.db),
                     fallback=lambda: request.db.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.Service_PATCH_ForbiddenResponseSchema.description,
                     content=err_svc_content)
    return ax.valid_http(http_success=HTTPOk, detail=s.Service_PATCH_OkResponseSchema.description,
                         content={"service": sf.format_service(service, show_private_url=True)})


@s.ServiceAPI.get(tags=[s.ServicesTag], response_schemas=s.Service_GET_responses)
@view_config(route_name=s.ServiceAPI.name, request_method="GET")
def get_service_view(request):
    """
    Get a service information.
    """
    service = ar.get_service_matchdict_checked(request)
    service_info = sf.format_service(service, show_private_url=True, show_resources_allowed=True)
    return ax.valid_http(http_success=HTTPOk, detail=s.Service_GET_OkResponseSchema.description,
                         content={"service": service_info})


@s.ServiceAPI.delete(schema=s.Service_DELETE_RequestSchema(), tags=[s.ServicesTag],
                     response_schemas=s.Service_DELETE_responses)
@view_config(route_name=s.ServiceAPI.name, request_method="DELETE")
def unregister_service_view(request):
    """
    Unregister a service.
    """
    service = ar.get_service_matchdict_checked(request)
    service_push = asbool(ar.get_multiformat_body(request, "service_push", default=False))
    svc_content = sf.format_service(service, show_private_url=True)
    svc_res_id = service.resource_id
    ax.evaluate_call(lambda: models.RESOURCE_TREE_SERVICE.delete_branch(resource_id=svc_res_id, db_session=request.db),
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail="Delete service from resource tree failed.", content=svc_content)

    def remove_service_magpie_and_phoenix(svc, svc_push, db_session):
        db_session.delete(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db_session.query(models.Service))

    ax.evaluate_call(lambda: remove_service_magpie_and_phoenix(service, service_push, request.db),
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.Service_DELETE_ForbiddenResponseSchema.description, content=svc_content)
    return ax.valid_http(http_success=HTTPOk, detail=s.Service_DELETE_OkResponseSchema.description)


@s.ServicePermissionsAPI.get(tags=[s.ServicesTag], response_schemas=s.ServicePermissions_GET_responses)
@view_config(route_name=s.ServicePermissionsAPI.name, request_method="GET")
def get_service_permissions_view(request):
    """
    List all applicable permissions for a service.
    """
    service = ar.get_service_matchdict_checked(request)
    svc_content = sf.format_service(service, show_private_url=True)
    svc_perms = ax.evaluate_call(lambda: [p.value for p in SERVICE_TYPE_DICT[service.type].permissions],
                                 fallback=request.db.rollback(), http_error=HTTPBadRequest, content=svc_content,
                                 msg_on_fail=s.ServicePermissions_GET_BadRequestResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.ServicePermissions_GET_OkResponseSchema.description,
                         content={"permission_names": format_permissions(svc_perms)})


@s.ServiceResourceAPI.delete(schema=s.ServiceResource_DELETE_RequestSchema(), tags=[s.ServicesTag],
                             response_schemas=s.ServiceResource_DELETE_responses)
@view_config(route_name=s.ServiceResourceAPI.name, request_method="DELETE")
def delete_service_resource_view(request):
    """
    Unregister a resource.
    """
    return ru.delete_resource(request)


@s.ServiceResourcesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceResources_GET_responses)
@view_config(route_name=s.ServiceResourcesAPI.name, request_method="GET")
def get_service_resources_view(request):
    """
    List all resources registered under a service.
    """
    service = ar.get_service_matchdict_checked(request)
    svc_res_json = sf.format_service_resources(service, db_session=request.db,
                                               show_all_children=True, show_private_url=True)
    return ax.valid_http(http_success=HTTPOk, content={svc_res_json["service_name"]: svc_res_json},
                         detail=s.ServiceResources_GET_OkResponseSchema.description)


@s.ServiceResourcesAPI.post(schema=s.ServiceResources_POST_RequestSchema, tags=[s.ServicesTag],
                            response_schemas=s.ServiceResources_POST_responses)
@view_config(route_name=s.ServiceResourcesAPI.name, request_method="POST")
def create_service_resource_view(request):
    """
    Register a new resource directly under a service or under one of its children resources.
    """
    service = ar.get_service_matchdict_checked(request)
    resource_name = ar.get_multiformat_body(request, "resource_name")
    resource_display_name = ar.get_multiformat_body(request, "resource_display_name", default=resource_name)
    resource_type = ar.get_multiformat_body(request, "resource_type")
    parent_id = ar.get_multiformat_body(request, "parent_id")  # no check because None/empty is allowed
    db_session = request.db
    if parent_id is None:
        parent_id = service.resource_id
    else:
        parent_id = ax.evaluate_call(lambda: int(parent_id),
                                     http_error=HTTPBadRequest,
                                     msg_on_fail=s.ServiceResources_POST_BadRequestResponseSchema.description)
        # validate target service is actually the root service of the provided parent resource ID
        root_service = ru.get_resource_root_service_by_id(parent_id, db_session=db_session)
        ax.verify_param(root_service, not_none=True, param_name="parent_id",
                        msg_on_fail=s.ServiceResources_POST_NotFoundResponseSchema.description,
                        http_error=HTTPNotFound)
        ax.verify_param(root_service.resource_id, is_equal=True,
                        param_compare=service.resource_id, param_name="parent_id",
                        msg_on_fail=s.ServiceResources_POST_BadRequestResponseSchema.description,
                        http_error=HTTPBadRequest)
    return ru.create_resource(resource_name, resource_display_name, resource_type,
                              parent_id=parent_id, db_session=db_session)


@s.ServiceTypeResourcesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceTypeResources_GET_responses)
@view_config(route_name=s.ServiceTypeResourcesAPI.name, request_method="GET")
def get_service_type_resources_view(request):
    """
    List details of resource types supported under a specific service type.
    """

    def _get_resource_types_info(res_type_names):
        res_type_classes = [rtc for rtn, rtc in models.RESOURCE_TYPE_DICT.items() if rtn in res_type_names]
        return [sf.format_service_resource_type(rtc, SERVICE_TYPE_DICT[service_type]) for rtc in res_type_classes]

    service_type = ar.get_value_matchdict_checked(request, "service_type")
    ax.verify_param(service_type, param_compare=SERVICE_TYPE_DICT.keys(), is_in=True, http_error=HTTPNotFound,
                    msg_on_fail=s.ServiceTypeResources_GET_NotFoundResponseSchema.description)
    resource_types_names = ax.evaluate_call(
        lambda: SERVICE_TYPE_DICT[service_type].resource_type_names,
        http_error=HTTPForbidden, content={"service_type": str(service_type)},
        msg_on_fail=s.ServiceTypeResourceTypes_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.ServiceTypeResourceTypes_GET_OkResponseSchema.description,
                         content={"resource_types": _get_resource_types_info(resource_types_names)})


@s.ServiceTypeResourceTypesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceTypeResourceTypes_GET_responses)
@view_config(route_name=s.ServiceTypeResourceTypesAPI.name, request_method="GET")
def get_service_type_resource_types_view(request):
    """
    List all resource types supported under a specific service type.
    """
    service_type = ar.get_value_matchdict_checked(request, "service_type")
    ax.verify_param(service_type, param_compare=SERVICE_TYPE_DICT.keys(), is_in=True, http_error=HTTPNotFound,
                    msg_on_fail=s.ServiceTypeResourceTypes_GET_NotFoundResponseSchema.description)
    resource_types = ax.evaluate_call(lambda: SERVICE_TYPE_DICT[service_type].resource_type_names,
                                      http_error=HTTPForbidden, content={"service_type": str(service_type)},
                                      msg_on_fail=s.ServiceTypeResourceTypes_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.ServiceTypeResourceTypes_GET_OkResponseSchema.description,
                         content={"resource_types": resource_types})
