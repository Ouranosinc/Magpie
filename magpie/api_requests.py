from magpie import *
from api_except import *
from ziggurat_definitions import *
from pyramid.interfaces import IAuthenticationPolicy, IAuthorizationPolicy
from management.resource.resource_utils import check_valid_service_resource_permission


def get_multiformat_post(request, key):
    if request.content_type == 'application/json':
        return evaluate_call(lambda: request.json_body.get(key),
                             httpError=HTTPInternalServerError,
                             msgOnFail="Key " + repr(key) + " could not be extracted from multiformat POST")
    return request.POST.get(key)


def get_multiformat_delete(request, key):
    return evaluate_call(lambda: request.json_body.get(key), httpError=HTTPInternalServerError,
                         msgOnFail="Key " + repr(key) + " could not be extracted from multiformat DELETE")


def get_permission_multiformat_post_checked(request, service_resource, permission_name_key='permission_name'):
    perm_name = get_value_multiformat_post_checked(request, permission_name_key)
    check_valid_service_resource_permission(perm_name, service_resource, request.db)
    return perm_name


def get_value_multiformat_post_checked(request, value_name_key):
    value_name = get_multiformat_post(request, value_name_key)
    verify_param(value_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `" + str(value_name_key) + "` value '" + str(value_name) + "' specified")
    return value_name


def get_userid_by_token(token, authn_policy):
    cookie_helper = authn_policy.cookie
    cookie = token
    if cookie is None:
        return None
    remote_addr = '0.0.0.0'

    timestamp, userid, tokens, user_data = cookie_helper.parse_ticket(
        cookie_helper.secret,
        cookie,
        remote_addr,
        cookie_helper.hashalg
    )
    return userid


def get_user(request, user_name_or_token):
    if user_name_or_token == LOGGED_USER:
        curr_user = request.user
        if curr_user:
            return curr_user
        else:
            anonymous = evaluate_call(lambda: UserService.by_user_name(ANONYMOUS_USER, db_session=request.db),
                                      fallback=lambda: request.db.rollback(),
                                      httpError=HTTPForbidden, msgOnFail="Anonymous user query refused by db")
            verify_param(anonymous, notNone=True, httpError=HTTPNotFound, msgOnFail="Anonymous user not found in db")
            return anonymous
    else:
        authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
        principals = authn_policy.effective_principals(request)
        admin_group = GroupService.by_group_name(ADMIN_GROUP, db_session=request.db)
        admin_principal = 'group:{}'.format(admin_group.id)
        if admin_principal not in principals:
            raise HTTPForbidden()
        user = evaluate_call(lambda: UserService.by_user_name(user_name_or_token, db_session=request.db),
                             fallback=lambda: request.db.rollback(),
                             httpError=HTTPForbidden, msgOnFail="User name query refused by db")
        verify_param(user, notNone=True, httpError=HTTPNotFound, msgOnFail="User name not found in db")
        return user


def get_user_matchdict_checked(request, user_name_key='user_name'):
    user_name = get_value_matchdict_checked(request, user_name_key)
    return get_user(request, user_name)


def get_group_matchdict_checked(request, group_name_key='group_name'):
    group_name = get_value_matchdict_checked(request, group_name_key)
    group = evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=request.db),
                          fallback=lambda: request.db.rollback(),
                          httpError=HTTPForbidden, msgOnFail="Group query by name refused by db")
    verify_param(group, notNone=True, httpError=HTTPNotFound, msgOnFail="Group name not found in db")
    return group


def get_resource_matchdict_checked(request, resource_name_key='resource_id'):
    resource_id = get_value_matchdict_checked(request, resource_name_key)
    resource_id = evaluate_call(lambda: int(resource_id), httpError=HTTPNotAcceptable,
                                msgOnFail="Resource ID is an invalid literal for `int` type")
    resource = evaluate_call(lambda: ResourceService.by_resource_id(resource_id, db_session=request.db),
                             fallback=lambda: request.db.rollback(),
                             httpError=HTTPForbidden, msgOnFail="Resource query by id refused by db")
    verify_param(resource, notNone=True, httpError=HTTPNotFound, msgOnFail="Resource ID not found in db")
    return resource


def get_service_matchdict_checked(request, service_name_key='service_name'):
    service_name = get_value_matchdict_checked(request, service_name_key)
    service = evaluate_call(lambda: models.Service.by_service_name(service_name, db_session=request.db),
                            fallback=lambda: request.db.rollback(),
                            httpError=HTTPForbidden, msgOnFail="Service query by name refused by db")
    verify_param(service, notNone=True, httpError=HTTPNotFound,
                 msgOnFail="Service name not found in db",
                 content={u'service_name': service_name})
    return service


def get_permission_matchdict_checked(request, service_resource, permission_name_key='permission_name'):
    perm_name = get_value_matchdict_checked(request, permission_name_key)
    check_valid_service_resource_permission(perm_name, service_resource, request.db)
    return perm_name


def get_value_matchdict_checked(request, key):
    val = request.matchdict.get(key)
    verify_param(val, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid value '" + str(val) + "' specified using key '" + str(key) + "'")
    return val
