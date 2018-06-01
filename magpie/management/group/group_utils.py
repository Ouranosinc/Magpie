from api_requests import *
from api_except import *
from models import resource_tree_service
from management.service.service_formats import format_service_resources, format_service
from group_formats import *
from ziggurat_definitions import *


def get_all_groups(db_session):
    group_names = evaluate_call(lambda: [grp.group_name for grp in models.Group.all(db_session=db_session)],
                                httpError=HTTPForbidden, msgOnFail="Obtain group names refused by db")
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
            display_all=False
        )
    return json_response


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


def get_group_services(resources_permissions_dict, db_session):
    grp_svc_dict = {}
    for res_id, perms in resources_permissions_dict.items():
        svc = models.Service.by_resource_id(resource_id=res_id, db_session=db_session)
        svc_type = str(svc.type)
        svc_name = str(svc.resource_name)
        if svc_type not in grp_svc_dict:
            grp_svc_dict[svc_type] = {}
        grp_svc_dict[svc_type][svc_name] = format_service(svc, perms)
    return grp_svc_dict


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


def get_group_services_permissions(group, db_session, resource_ids=None):
    def get_grp_svc_perms(grp, db_ses, res_ids):
        res_perms = get_group_resources_permissions_dict(grp, resource_types=[u'service'],
                                                         db_session=db_ses, resource_ids=res_ids)
        grp_svc_perms = []
        for res_id, res_perm in res_perms.items():
            svc = models.Service.by_resource_id(res_id, db_session=db_ses)
            grp_svc_perms.append((svc, res_perm))
        return grp_svc_perms

    return evaluate_call(lambda: get_grp_svc_perms(group, db_session, resource_ids), httpError=HTTPInternalServerError,
                         msgOnFail="Failed to obtain group service permissions",
                         content={u'group': format_group(group), u'resource_ids': repr(resource_ids)})


def get_group_service_resources_permissions_dict(group, service, db_session):
    res_under_svc = resource_tree_service.from_parent_deeper(parent_id=service.resource_id, db_session=db_session)
    res_ids = [resource.Resource.resource_id for resource in res_under_svc]
    return get_group_resources_permissions_dict(group, db_session, resource_types=None, resource_ids=res_ids)
