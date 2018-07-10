from definitions.pyramid_definitions import *
from models import resource_tree_service, Service
from services import service_type_dict
from api.api_except import evaluate_call


def format_resource(resource, permissions=None, basic_info=False):
    def fmt_res(res, perms, info):
        if info:
            return {
                u'resource_name': str(res.resource_name),
                u'resource_type': str(res.resource_type),
                u'resource_id': res.resource_id
            }
        return {
            u'resource_name': str(res.resource_name),
            u'resource_type': str(res.resource_type),
            u'resource_id': res.resource_id,
            u'parent_id': res.parent_id,
            u'root_service_id': res.root_service_id,
            u'children': {},
            u'permission_names': list() if perms is None else sorted(perms)
        }

    return evaluate_call(
        lambda: fmt_res(resource, permissions, basic_info),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format resource.",
        content={u'resource': repr(resource), u'permissions': repr(permissions), u'basic_info': str(basic_info)}
    )


def format_resource_tree(children, db_session, resources_perms_dict=None, internal_svc_res_perm_dict=None):
    """

    :param children:
    :param db_session:
    :param resources_perms_dict: any pre-established user- or group-specific permissions. Only those are shown if given
    :param internal_svc_res_perm_dict: *for this function's use only*,
    avoid re-fetch of already obtained permissions for corresponding resources
    :return:
    """
    internal_svc_res_perm_dict = dict() if internal_svc_res_perm_dict is None else internal_svc_res_perm_dict

    fmt_res_tree = {}
    for child_id, child_dict in children.items():
        resource = child_dict[u'node']
        new_children = child_dict[u'children']
        perms = []

        # case of pre-specified user/group-specific permissions
        if resources_perms_dict is not None:
            if resource.resource_id in resources_perms_dict.keys():
                perms = resources_perms_dict[resource.resource_id]

        # case of full fetch (permitted resource permissions)
        else:
            # directly access the resource if it is a service
            if resource.root_service_id is None:
                service = resource
                service_id = resource.resource_id
                # add to dict only if not already added
                if service_id not in internal_svc_res_perm_dict:
                    internal_svc_res_perm_dict[service_id] = service_type_dict[service.type].resource_types_permissions
            # obtain corresponding top-level service resource if not already available
            else:
                service_id = resource.root_service_id
                if service_id not in internal_svc_res_perm_dict:
                    service = Service.by_resource_id(service_id, db_session=db_session)
                    internal_svc_res_perm_dict[service_id] = service_type_dict[service.type].resource_types_permissions

            perms = internal_svc_res_perm_dict[service_id][resource.resource_type]

        fmt_res_tree[child_id] = format_resource(resource, perms)
        fmt_res_tree[child_id][u'children'] = format_resource_tree(new_children, db_session,
                                                                   resources_perms_dict, internal_svc_res_perm_dict)

    return fmt_res_tree


def get_resource_children(resource, db_session):
    query = resource_tree_service.from_parent_deeper(resource.resource_id, db_session=db_session)
    tree_struct_dict = resource_tree_service.build_subtree_strut(query)
    return tree_struct_dict[u'children']


def format_resource_with_children(resource, db_session):
    resource_formatted = format_resource(resource)

    resource_formatted[u'children'] = format_resource_tree(
        get_resource_children(resource, db_session),
        db_session=db_session
    )
    return resource_formatted
