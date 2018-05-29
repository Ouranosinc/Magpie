from api_requests import *


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
            u'children': {},
            u'permission_names': list() if perms is None else perms
        }

    return evaluate_call(
        lambda: fmt_res(resource, permissions, basic_info),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format resource",
        content={u'service': repr(resource), u'permissions': repr(permissions), u'basic_info': str(basic_info)}
    )


def format_resource_tree(children, db_session, resources_perms_dict=None):
    fmt_res_tree = {}
    for child_id, child_dict in children.items():
        resource = child_dict[u'node']
        new_children = child_dict[u'children']
        perms = []

        resources_perms_dict = dict() if resources_perms_dict is None else resources_perms_dict
        if resource.resource_id in resources_perms_dict.keys():
            perms = resources_perms_dict[resource.resource_id]

        fmt_res_tree[child_id] = format_resource(resource, perms)
        fmt_res_tree[child_id][u'children'] = format_resource_tree(new_children, db_session, resources_perms_dict)

    return fmt_res_tree
