from magpie import *
import models
from models import resource_type_dict
from models import resource_tree_service
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
    db = db_session
    if group is None:
        raise HTTPBadRequest(detail='This group does not exist')
    resource_permission_tuple = group.resources_with_possible_perms(resource_ids=resource_ids, resource_types=resource_types, db_session=db)
    resources_permissions_dict = {}
    for tuple in resource_permission_tuple:
        if tuple.resource.resource_id not in resources_permissions_dict:
            resources_permissions_dict[tuple.resource.resource_id] = [tuple.perm_name]
        else:
            resources_permissions_dict[tuple.resource.resource_id].append(tuple.perm_name)

    return resources_permissions_dict


def get_group_service_resources_permissions_dict(group, service, db_session):
    resources_under_service = resource_tree_service.from_parent_deeper(parent_id=service.resource_id, db_session=db_session)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    return get_group_resources_permissions_dict(group, db_session, resource_types=None, resource_ids=resource_ids)


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
    if resource.owner_group_id == group.id:
        permission_names = resource_type_dict[resource.type].permission_names
    else:
        group_res_permission = db_session.query(models.GroupResourcePermission) \
            .filter(models.GroupResourcePermission.resource_id == resource.resource_id) \
            .filter(models.GroupResourcePermission.group_id == group.id)
        permission_names = [permission.perm_name for permission in group_res_permission]
    return permission_names


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



    group_name = request.matchdict.get('group_name')
    resource_id = request.matchdict.get('resource_id')
    permission_name = request.matchdict.get('permission_name')

    db = request.db
    resource = ResourceService.by_resource_id(resource_id, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)

    if resource is None or group is None:
        raise HTTPNotFound(detail='this service/group does not exist')

    if resource.resource_type == models.Service.resource_type_name:
        if permission_name not in service_type_dict[resource.type].permission_names:
            raise HTTPBadRequest(detail='This permission is not allowed for that service')
    elif permission_name not in resource_type_dict[resource.resource_type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that resource')

    return delete_group_resource_permission(permission_name, resource.resource_id, group.id, db_session=db)


@view_config(route_name='group_service_resources', request_method='GET')
def get_group_service_resources_view(request):
    service_name = request.matchdict.get('service_name')
    group_name = request.matchdict.get('group_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if service is None or group is None:
        raise HTTPNotFound(detail='this service/group does not exist')

    service_perms = get_group_service_permissions(group=group, service=service, db_session=db)

    resources_perms_dict = get_group_service_resources_permissions_dict(group=group,
                                                                        service=service,
                                                                        db_session=db)
    json_response = format_service_resources(
        service=service,
        db_session=db,
        service_perms=service_perms,
        resources_perms_dict=resources_perms_dict,
        display_all=False
    )

    return HTTPOk(
            body=json.dumps({'service': json_response}),
            content_type='application/json'
        )



