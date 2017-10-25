from magpie import *
import models
from models import resource_type_dict, resource_tree_service
from management.service.service import format_service_resources, format_service
from services import service_type_dict
from api_requests import *
from api_except import *


def format_group(group):
    def fmt_grp(grp):
        return {
            u'group_name': str(grp.group_name),
            u'description': str(grp.description),
            u'member_count': grp.member_count,
            u'group_id': grp.id,
            u'users': grp.users
        }

    return evaluate_call(
        lambda: fmt_grp(group), httpError=HTTPInternalServerError,
        msgOnFail="Failed to format group", content={u'group': repr(group)}
    )


@view_config(route_name='groups', request_method='GET')
def get_groups(request):
    group_names = evaluate_call(lambda: [grp.group_name for grp in models.Group.all(db_session=request.db)],
                                httpError=HTTPForbidden, msgOnFail="Obtain group names refused by db")
    return valid_http(httpSuccess=HTTPOk, detail="Get groups successful", content={u'group_names': group_names})


@view_config(route_name='groups', request_method='POST')
def create_group(request):
    group_name = get_multiformat_post(request, 'group_name')
    new_group = evaluate_call(lambda: models.Group(group_name=group_name), fallback=lambda: request.db.rollback(),
                              httpError=HTTPForbidden, msgOnFail="Create new group by name refused by db",
                              content={u'group_name': str(group_name)})
    evaluate_call(lambda: request.db.add(new_group), fallback=lambda: request.db.rollback(),
                  httpError=HTTPConflict, msgOnFail="Add new group by name refused by db",
                  content={u'group_name': str(group_name)})
    return valid_http(httpSuccess=HTTPCreated, detail="Create group successful",
                      content={u'group': format_group(new_group)})


@view_config(route_name='group', request_method='DELETE')
def delete_group(request):
    group = get_group_matchdict_checked(request)
    evaluate_call(lambda: request.db.delete(group), fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete group forbidden by db")
    return valid_http(httpSuccess=HTTPOk, detail="Delete group successful")


@view_config(route_name='group_users', request_method='GET')
def get_group_users(request):
    group = get_group_matchdict_checked(request)
    user_names = evaluate_call(lambda: [user.user_name for user in group.users],
                               httpError=HTTPForbidden, msgOnFail="Failed to obtain group user names from db")
    return valid_http(httpSuccess=HTTPOk, detail="Get group users successful", content={u'user_names': user_names})


@view_config(route_name='group_services', request_method='GET')
def get_group_services_view(request):
    group = get_group_matchdict_checked(request)
    res_perm_dict = get_group_resources_permissions_dict(group, resource_types=[u'service'], db_session=request.db)

    def get_grp_svc(res_perm):
        grp_svc_dict = {}
        for res_id, perms in res_perm.items():
            svc = models.Service.by_resource_id(resource_id=res_id, db_session=request.db)
            svc_type = str(svc.type)
            svc_name = str(svc.resource_name)
            if svc_type not in grp_svc_dict:
                grp_svc_dict[svc_type] = {}
            grp_svc_dict[svc_type][svc_name] = format_service(svc, perms)
        return grp_svc_dict

    grp_svc_json = evaluate_call(lambda: get_grp_svc(res_perm_dict), httpError=HTTPInternalServerError,
                                 msgOnFail="Failed to populate group services", content={u'group': format_group(group)})
    return valid_http(httpSuccess=HTTPOk, detail="Get group services successful", content={u'services': grp_svc_json})


def get_group_services_permissions(group, db_session, resource_ids=None):
    def get_grp_svc_perms(grp, db, res_ids):
        res_perms = get_group_resources_permissions_dict(grp, resource_types=[u'service'],
                                                         db_session=db, resource_ids=res_ids)
        grp_svc_perms = []
        for res_id, res_perm in res_perms.items():
            svc = models.Service.by_resource_id(res_id, db_session=db)
            grp_svc_perms.append((svc, res_perm))
        return grp_svc_perms

    return evaluate_call(lambda: get_grp_svc_perms(group, db_session, resource_ids), httpError=HTTPInternalServerError,
                         msgOnFail="Failed to obtain group service permissions",
                         content={u'group': format_group(group), u'resource_ids': repr(resource_ids)})


@view_config(route_name='group_service_permissions', request_method='GET')
def get_group_service_permissions_view(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)

    def get_grp_svc_perms(grp, svc, db):
        if svc.owner_group_id == grp.id:
            svc_found = svc
            perms_found = service_type_dict[svc.type].permission_names
        else:
            svc_perm_list = get_group_services_permissions(grp, db_session=db, resource_ids=[svc.resource_id])
            svc_found, perms_found = svc_perm_list[0]
        return svc_found, perms_found

    found = evaluate_call(lambda: get_grp_svc_perms(group, service, request.db), httpError=HTTPInternalServerError,
                          msgOnFail="Failed to extract permissions names from group-service",
                          content={u'group': format_group(group), u'service': format_service(service)})
    service_found, permission_names = found
    return valid_http(httpSuccess=HTTPOk, detail="Get group service permissions successful",
                      content={u'permission_names': permission_names})


@view_config(route_name='group_service_permissions', request_method='POST')
def create_group_service_permission(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    permission_name = get_permission_multiformat_post_checked(request, service)
    return create_group_resource_permission(permission_name, service.resource_id, group.id, db_session=request.db)


@view_config(route_name='group_service_permission', request_method='DELETE')
def delete_group_service_permission(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    permission_name = get_permission_multiformat_post_checked(request, service)
    return delete_group_resource_permission(permission_name, service.resource_id, group.id, db_session=request.db)


def get_group_resources_permissions_dict(group, db_session, resource_ids=None, resource_types=None):
    def get_grp_res_perm(grp, db, res_ids, res_types):
        res_perms_tup = grp.resources_with_possible_perms(resource_ids=res_ids, resource_types=res_types, db_session=db)
        res_perms_dict = {}
        for res_perm in res_perms_tup:
            if res_perm.resource.resource_id not in res_perms_dict:
                res_perms_dict[res_perm.resource.resource_id] = [res_perm.perm_name]
            else:
                res_perms_dict[res_perm.resource.resource_id].append(res_perm.perm_name)
        return res_perms_dict

    return evaluate_call(lambda: get_grp_res_perm(group, db_session, resource_ids, resource_types),
                         fallback=lambda: db_session.rollback(),
                         httpError=HTTPInternalServerError, msgOnFail="Failed to build group resources json tree",
                         content={u'group': repr(group), u'resource_ids': repr(resource_ids),
                                  u'resource_types': repr(resource_types)})


def get_group_service_resources_permissions_dict(group, service, db_session):
    res_under_svc = resource_tree_service.from_parent_deeper(parent_id=service.resource_id, db_session=db_session)
    res_ids = [resource.Resource.resource_id for resource in res_under_svc]
    return get_group_resources_permissions_dict(group, db_session, resource_types=None, resource_ids=res_ids)


@view_config(route_name='group_resources', request_method='GET')
def get_group_resources_view(request):
    group = get_group_matchdict_checked(request)

    def get_grp_res(grp, db):
        json_response = {}
        for svc in models.Service.all(db_session=db):
            svc_perms = get_group_service_permissions(group=grp, service=svc, db_session=db)
            svc_name = str(svc.resource_name)
            svc_type = str(svc.type)
            if svc_type not in json_response:
                json_response[svc_type] = {}
            res_perm_dict = get_group_service_resources_permissions_dict(group=grp, service=svc, db_session=db)
            json_response[svc_type][svc_name] = format_service_resources(
                svc,
                db_session=db,
                service_perms=svc_perms,
                resources_perms_dict=res_perm_dict,
                display_all=False
            )
        return json_response

    grp_res_json = evaluate_call(lambda: get_grp_res(group, request.db), fallback=lambda: request.db.rollback(),
                                 httpError=HTTPInternalServerError, content={u'group': repr(group)},
                                 msgOnFail="Failed to build group resources json tree")
    return valid_http(httpSuccess=HTTPOk, detail="Get group resources successful", content={u'resources': grp_res_json})


def get_group_resource_permissions(group, resource, db_session):
    def get_grp_res_perms(grp, res, db):
        if res.owner_group_id == grp.id:
            perm_names = resource_type_dict[res.type].permission_names
        else:
            grp_res_perm = db.query(models.GroupResourcePermission) \
                .filter(models.GroupResourcePermission.resource_id == res.resource_id) \
                .filter(models.GroupResourcePermission.group_id == grp.id)
            perm_names = [permission.perm_name for permission in grp_res_perm]
        return perm_names

    return evaluate_call(lambda: get_grp_res_perms(group, resource, db_session), httpError=HTTPInternalServerError,
                         msgOnFail="Failed to obtain group resource permissions",
                         content={u'group': repr(group), u'resource': repr(resource)})


def get_group_service_permissions(group, service, db_session):
    def get_grp_svc_perms(grp, svc, db):
        if svc.owner_group_id == grp.id:
            perm_names = service_type_dict[svc.type].permission_names
        else:
            grp_res_perm = db.query(models.GroupResourcePermission) \
                .filter(models.GroupResourcePermission.resource_id == svc.resource_id) \
                .filter(models.GroupResourcePermission.group_id == grp.id)
            perm_names = [perm.perm_name for perm in grp_res_perm]
        return perm_names

    return evaluate_call(lambda: get_grp_svc_perms(group, service, db_session), httpError=HTTPInternalServerError,
                         msgOnFail="Failed to obtain group service permissions",
                         content={u'group': repr(group), u'service': repr(service)})


@view_config(route_name='group_resource_permissions', request_method='GET')
def get_group_resource_permissions_view(request):
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_names = get_group_resource_permissions(group, resource, db_session=request.db)
    return valid_http(httpSuccess=HTTPOk, detail="Get group resource permissions successful",
                      content={u'permission_names': perm_names})


def create_group_resource_permission(permission_name, resource_id, group_id, db_session):
    perm_content = {u'permission_name': str(permission_name), u'resource_id': resource_id, u'group_id': group_id}
    new_perm = evaluate_call(lambda: models.GroupResourcePermission(resource_id=resource_id, group_id=group_id),
                             fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
                             msgOnFail="Create group resource permission failed", content=perm_content)
    new_perm.perm_name = permission_name
    evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(), httpError=HTTPConflict,
                  msgOnFail="Add group resource permission refused by db", content=perm_content)
    return valid_http(httpSuccess=HTTPCreated, detail="Create group resource permission successful",
                      content=perm_content)


@view_config(route_name='group_resource_permissions', request_method='POST')
def create_group_resource_permission_view(request):
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    permission_name = get_permission_multiformat_post_checked(request, resource)
    return create_group_resource_permission(permission_name, resource.resource_id, group.id, db_session=request.db)


def delete_group_resource_permission(permission_name, resource_id, group_id, db_session):
    perm_content = {u'permission_name': str(permission_name), u'resource_id': resource_id, u'group_id': group_id}
    del_perm = evaluate_call(
        lambda: GroupResourcePermissionService.get(group_id, resource_id, permission_name, db_session=db_session),
        fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
        msgOnFail="Get group resource permission failed", content=perm_content
    )
    evaluate_call(lambda: db_session.delete(del_perm), fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete group resource permission refused by db", content=perm_content)
    return valid_http(httpSuccess=HTTPOk, detail="Delete group resource permission successful")


@view_config(route_name='group_resource_permission', request_method='DELETE')
def delete_group_resource_permission_view(request):
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    permission_name = get_permission_multiformat_post_checked(request, resource)
    return delete_group_resource_permission(permission_name, resource.resource_id, group.id, db_session=request.db)


@view_config(route_name='group_service_resources', request_method='GET')
def get_group_service_resources_view(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    svc_perms = get_group_service_permissions(group=group, service=service, db_session=request.db)
    res_perms = get_group_service_resources_permissions_dict(group=group, service=service, db_session=request.db)
    svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=svc_perms,
        resources_perms_dict=res_perms,
        display_all=False
    )
    return valid_http(httpSuccess=HTTPOk, detail="Get group service resources successful",
                      content={u'service': svc_res_json})
