from magpie.services import SERVICE_TYPE_DICT
from magpie.api import api_except as ax, api_rest_schemas as s
from magpie.api.management.resource.resource_utils import check_valid_service_resource_permission
from magpie.api.management.resource.resource_formats import format_resource
from magpie.api.management.service.service_formats import format_service_resources, format_service
from magpie.api.management.group.group_formats import format_group
from magpie.definitions.ziggurat_definitions import GroupService, GroupResourcePermissionService, ResourceService
from magpie.definitions.pyramid_definitions import (
    HTTPOk,
    HTTPCreated,
    HTTPForbidden,
    HTTPNotFound,
    HTTPConflict,
    HTTPInternalServerError
)
from magpie import models
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.pyramid_definitions import HTTPException  # noqa: F401
    from magpie.definitions.sqlalchemy_definitions import Session  # noqa: F401
    from magpie.definitions.typedefs import Str  # noqa: F401


def get_all_groups(db_session):
    group_names = ax.evaluate_call(lambda: [grp.group_name for grp in models.Group.all(db_session=db_session)],
                                   httpError=HTTPForbidden, msgOnFail=s.Groups_GET_ForbiddenResponseSchema.description)
    return group_names


def get_group_resources(group, db_session):
    json_response = {}
    for svc in models.Service.all(db_session=db_session):
        svc_perms = get_group_service_permissions(group=group, service=svc, db_session=db_session)
        svc_name = str(svc.resource_name)
        svc_type = str(svc.type)
        if svc_type not in json_response:
            json_response[svc_type] = {}
        res_perm_dict = get_group_service_resources_permissions_dict(group=group, service=svc, db_session=db_session)
        json_response[svc_type][svc_name] = format_service_resources(
            svc,
            db_session=db_session,
            service_perms=svc_perms,
            resources_perms_dict=res_perm_dict,
            show_all_children=False,
            show_private_url=False,
        )
    return json_response


def create_group(group_name, db_session):
    # type: (Str, Session) -> HTTPException
    """
    Creates a group if it is permitted and not conflicting.
    :returns: corresponding HTTP response according to the encountered situation.
    """
    group = GroupService.by_group_name(group_name, db_session=db_session)
    group_content_error = {u'group_name': str(group_name)}
    ax.verify_param(group, isNone=True, httpError=HTTPConflict, withParam=False,
                    msgOnFail=s.Groups_POST_ConflictResponseSchema.description, content=group_content_error)
    # noinspection PyArgumentList
    new_group = ax.evaluate_call(lambda: models.Group(group_name=group_name), fallback=lambda: db_session.rollback(),
                                 httpError=HTTPForbidden, content=group_content_error,
                                 msgOnFail=s.Groups_POST_ForbiddenCreateResponseSchema.description)
    ax.evaluate_call(lambda: db_session.add(new_group), fallback=lambda: db_session.rollback(),
                     httpError=HTTPForbidden, content=group_content_error,
                     msgOnFail=s.Groups_POST_ForbiddenAddResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPCreated, detail=s.Groups_POST_CreatedResponseSchema.description,
                         content={u'group': format_group(new_group, basic_info=True)})


def create_group_resource_permission(permission_name, resource, group, db_session):
    # type: (Str, models.Resource, models.Group, Session) -> HTTPException
    """
    Creates a permission on a group/resource combination if it is permitted and not conflicting.
    :returns: corresponding HTTP response according to the encountered situation.
    """
    resource_id = resource.resource_id
    check_valid_service_resource_permission(permission_name, resource, db_session)
    perm_content = {u'permission_name': str(permission_name),
                    u'resource': format_resource(resource, basic_info=True),
                    u'group': format_group(group, basic_info=True)}
    create_perm = ax.evaluate_call(
        lambda: GroupResourcePermissionService.get(group.id, resource_id, permission_name, db_session=db_session),
        fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
        msgOnFail=s.GroupResourcePermissions_POST_ForbiddenGetResponseSchema.description, content=perm_content
    )
    ax.verify_param(create_perm, isNone=True, httpError=HTTPConflict,
                    msgOnFail=s.GroupResourcePermissions_POST_ConflictResponseSchema.description, content=perm_content)
    # noinspection PyArgumentList
    new_perm = ax.evaluate_call(lambda: models.GroupResourcePermission(resource_id=resource_id, group_id=group.id),
                                fallback=lambda: db_session.rollback(), httpError=HTTPForbidden, content=perm_content,
                                msgOnFail=s.GroupResourcePermissions_POST_ForbiddenCreateResponseSchema.description)
    new_perm.perm_name = permission_name
    ax.evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(),
                     httpError=HTTPForbidden, content=perm_content,
                     msgOnFail=s.GroupResourcePermissions_POST_ForbiddenAddResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPCreated, content=perm_content,
                         detail=s.GroupResourcePermissions_POST_CreatedResponseSchema.description)


def get_group_resources_permissions_dict(group, db_session, resource_ids=None, resource_types=None):
    def get_grp_res_perm(grp, db, res_ids, res_types):
        res_perms_tup = GroupService.resources_with_possible_perms(
            grp, resource_ids=res_ids, resource_types=res_types, db_session=db)
        res_perms_dict = {}
        for res_perm in res_perms_tup:
            if res_perm.resource.resource_id not in res_perms_dict:
                res_perms_dict[res_perm.resource.resource_id] = [res_perm.perm_name]
            else:
                res_perms_dict[res_perm.resource.resource_id].append(res_perm.perm_name)
        return res_perms_dict

    return ax.evaluate_call(lambda: get_grp_res_perm(group, db_session, resource_ids, resource_types),
                            fallback=lambda: db_session.rollback(),
                            httpError=HTTPInternalServerError,
                            msgOnFail=s.GroupResourcesPermissions_InternalServerErrorResponseSchema.description,
                            content={u'group': repr(group), u'resource_ids': repr(resource_ids),
                                     u'resource_types': repr(resource_types)})


def get_group_resource_permissions(group, resource, db_session):
    def get_grp_res_perms(grp, res, db):
        if res.owner_group_id == grp.id:
            perm_names = models.resource_type_dict[res.type].permission_names
        else:
            grp_res_perm = db.query(models.GroupResourcePermission) \
                .filter(models.GroupResourcePermission.resource_id == res.resource_id) \
                .filter(models.GroupResourcePermission.group_id == grp.id)
            perm_names = [permission.perm_name for permission in grp_res_perm]
        return perm_names

    return ax.evaluate_call(lambda: get_grp_res_perms(group, resource, db_session), httpError=HTTPInternalServerError,
                            msgOnFail=s.GroupResourcePermissions_InternalServerErrorResponseSchema.description,
                            content={u'group': repr(group), u'resource': repr(resource)})


def delete_group_resource_permission(permission_name, resource, group, db_session):
    resource_id = resource.resource_id
    check_valid_service_resource_permission(permission_name, resource, db_session)
    perm_content = {u'permission_name': str(permission_name),
                    u'resource': format_resource(resource, basic_info=True),
                    u'group': format_group(group, basic_info=True)}
    del_perm = ax.evaluate_call(
        lambda: GroupResourcePermissionService.get(group.id, resource_id, permission_name, db_session=db_session),
        fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
        msgOnFail=s.GroupServicePermission_DELETE_ForbiddenGetResponseSchema.description, content=perm_content
    )
    ax.verify_param(del_perm, notNone=True, httpError=HTTPNotFound, content=perm_content,
                    msgOnFail=s.GroupServicePermission_DELETE_NotFoundResponseSchema.description)
    ax.evaluate_call(lambda: db_session.delete(del_perm), fallback=lambda: db_session.rollback(),
                     httpError=HTTPForbidden, content=perm_content,
                     msgOnFail=s.GroupServicePermission_DELETE_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.GroupServicePermission_DELETE_OkResponseSchema.description)


def get_group_services(resources_permissions_dict, db_session):
    grp_svc_dict = {}
    for res_id, perms in resources_permissions_dict.items():
        svc = ResourceService.by_resource_id(resource_id=res_id, db_session=db_session)
        svc_type = str(svc.type)
        svc_name = str(svc.resource_name)
        if svc_type not in grp_svc_dict:
            grp_svc_dict[svc_type] = {}
        grp_svc_dict[svc_type][svc_name] = format_service(svc, perms, show_private_url=False)
    return grp_svc_dict


def get_group_service_permissions(group, service, db_session):
    def get_grp_svc_perms(grp, svc, db):
        if svc.owner_group_id == grp.id:
            perm_names = SERVICE_TYPE_DICT[svc.type].permission_names
        else:
            grp_res_perm = db.query(models.GroupResourcePermission) \
                .filter(models.GroupResourcePermission.resource_id == svc.resource_id) \
                .filter(models.GroupResourcePermission.group_id == grp.id)
            perm_names = [perm.perm_name for perm in grp_res_perm]
        return perm_names

    return ax.evaluate_call(lambda: get_grp_svc_perms(group, service, db_session),
                            httpError=HTTPInternalServerError,
                            msgOnFail="Failed to obtain group service permissions",
                            content={u'group': repr(group), u'service': repr(service)})


def get_group_services_permissions(group, db_session, resource_ids=None):
    def get_grp_svc_perms(grp, db_ses, res_ids):
        res_perms = get_group_resources_permissions_dict(
            grp, resource_types=[models.Service.resource_type_name], db_session=db_ses, resource_ids=res_ids
        )
        grp_svc_perms = []
        for res_id, res_perm in res_perms.items():
            svc = ResourceService.by_resource_id(res_id, db_session=db_ses)
            grp_svc_perms.append((svc, res_perm))
        return grp_svc_perms

    return ax.evaluate_call(lambda: get_grp_svc_perms(group, db_session, resource_ids),
                            httpError=HTTPInternalServerError,
                            msgOnFail="Failed to obtain group service permissions",
                            content={u'group': format_group(group), u'resource_ids': repr(resource_ids)})


def get_group_service_resources_permissions_dict(group, service, db_session):
    res_id = service.resource_id
    res_under_svc = models.resource_tree_service.from_parent_deeper(parent_id=res_id, db_session=db_session)
    res_ids = [resource.Resource.resource_id for resource in res_under_svc]
    return get_group_resources_permissions_dict(group, db_session, resource_types=None, resource_ids=res_ids)
