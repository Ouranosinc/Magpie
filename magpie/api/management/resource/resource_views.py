from pyramid.httpexceptions import HTTPBadRequest, HTTPForbidden, HTTPInternalServerError, HTTPOk
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.resource import resource_formats as rf
from magpie.api.management.resource import resource_utils as ru
from magpie.api.management.service.service_formats import format_service_resources
from magpie.api.management.service.service_utils import get_services_by_type
from magpie.permissions import format_permissions
from magpie.register import sync_services_phoenix
from magpie.services import SERVICE_TYPE_DICT


@s.ResourcesAPI.get(tags=[s.ResourcesTag], response_schemas=s.Resources_GET_responses)
@view_config(route_name=s.ResourcesAPI.name, request_method="GET")
def get_resources_view(request):
    """
    List all registered resources.
    """
    res_json = {}
    for svc_type in SERVICE_TYPE_DICT:
        services = get_services_by_type(svc_type, db_session=request.db)
        res_json[svc_type] = {}
        for svc in services:
            res_json[svc_type][svc.resource_name] = format_service_resources(
                svc, request.db, show_all_children=True, show_private_url=False)
    res_json = {"resources": res_json}
    return ax.valid_http(http_success=HTTPOk, detail=s.Resources_GET_OkResponseSchema.description, content=res_json)


@s.ResourceAPI.get(tags=[s.ResourcesTag], response_schemas=s.Resource_GET_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="GET")
def get_resource_view(request):
    """
    Get resource information.
    """
    resource = ar.get_resource_matchdict_checked(request)
    res_json = ax.evaluate_call(lambda: rf.format_resource_with_children(resource, db_session=request.db),
                                fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                                msg_on_fail=s.Resource_GET_InternalServerErrorResponseSchema.description,
                                content={"resource": rf.format_resource(resource, basic_info=True)})
    return ax.valid_http(http_success=HTTPOk, content={"resource": res_json},
                         detail=s.Resource_GET_OkResponseSchema.description)


@s.ResourcesAPI.post(schema=s.Resources_POST_RequestSchema, tags=[s.ResourcesTag],
                     response_schemas=s.Resources_POST_responses)
@view_config(route_name=s.ResourcesAPI.name, request_method="POST")
def create_resource_view(request):
    """
    Register a new resource.
    """
    resource_name = ar.get_value_multiformat_body_checked(request, "resource_name")
    resource_display_name = ar.get_multiformat_body(request, "resource_display_name", default=resource_name)
    resource_type = ar.get_value_multiformat_body_checked(request, "resource_type")
    parent_id = ar.get_value_multiformat_body_checked(request, "parent_id", pattern=ax.INDEX_REGEX)
    return ru.create_resource(resource_name, resource_display_name, resource_type, parent_id, request.db)


@s.ResourceAPI.delete(schema=s.Resource_DELETE_RequestSchema(), tags=[s.ResourcesTag],
                      response_schemas=s.Resources_DELETE_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="DELETE")
def delete_resource_view(request):
    """
    Unregister a resource.
    """
    return ru.delete_resource(request)


@s.ResourceAPI.patch(schema=s.Resource_PATCH_RequestSchema(), tags=[s.ResourcesTag],
                     response_schemas=s.Resource_PATCH_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="PATCH")
def update_resource(request):
    """
    Update a resource information.
    """
    resource = ar.get_resource_matchdict_checked(request, "resource_id")
    service_push = asbool(ar.get_multiformat_body(request, "service_push"))
    res_old_name = resource.resource_name
    res_new_name = ar.get_value_multiformat_body_checked(request, "resource_name")

    def rename_service_magpie_and_phoenix(res, new_name, svc_push, db):
        if res.resource_type != "service":
            svc_push = False
        res.resource_name = new_name
        if svc_push:
            sync_services_phoenix(db.query(models.Service))

    ax.evaluate_call(lambda: rename_service_magpie_and_phoenix(resource, res_new_name, service_push, request.db),
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.Resource_PATCH_ForbiddenResponseSchema.description,
                     content={"resource_id": resource.resource_id, "resource_name": resource.resource_name,
                              "old_resource_name": res_old_name, "new_resource_name": res_new_name})
    return ax.valid_http(http_success=HTTPOk, detail=s.Resource_PATCH_OkResponseSchema.description,
                         content={"resource_id": resource.resource_id, "resource_name": resource.resource_name,
                                  "old_resource_name": res_old_name, "new_resource_name": res_new_name})


@s.ResourcePermissionsAPI.get(tags=[s.ResourcesTag], response_schemas=s.ResourcePermissions_GET_responses)
@view_config(route_name=s.ResourcePermissionsAPI.name, request_method="GET")
def get_resource_permissions_view(request):
    """
    List all applicable permissions for a resource.
    """
    resource = ar.get_resource_matchdict_checked(request, "resource_id")
    res_perm = ax.evaluate_call(lambda: ru.get_resource_permissions(resource, db_session=request.db),
                                fallback=lambda: request.db.rollback(), http_error=HTTPBadRequest,
                                msg_on_fail=s.ResourcePermissions_GET_BadRequestResponseSchema.description,
                                content={"resource": rf.format_resource(resource, basic_info=True)})
    return ax.valid_http(http_success=HTTPOk, detail=s.ResourcePermissions_GET_OkResponseSchema.description,
                         content={"permission_names": format_permissions(res_perm)})
