import json

from authomatic.adapters import WebObAdapter
from pyramid.httpexceptions import *
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.response import Response
from pyramid.security import NO_PERMISSION_REQUIRED, Authenticated
from pyramid.view import view_config
from pyramid.security import remember

from ziggurat_foundations.ext.pyramid.sign_in import ZigguratSignInBadAuth
from ziggurat_foundations.ext.pyramid.sign_in import ZigguratSignInSuccess
from ziggurat_foundations.ext.pyramid.sign_in import ZigguratSignOut
from ziggurat_foundations.models.services.external_identity import ExternalIdentityService
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.ext.pyramid import get_user
from security import authomatic
from api_except import *
from api_requests import *
import requests
import models

from magpie import *
from management.user.user import create_user

internal_providers = [u'ziggurat']
external_providers = [u'openid',
                      u'dkrz',
                      u'ipsl',
                      u'badc',
                      u'pcmdi',
                      u'smhi',
                      u'github']
providers = internal_providers + external_providers


def sign_in_internal(request, data):
    """
    redirection to ziggurat sign in
    """
    ziggu_url = request.route_url('ziggurat.routes.sign_in')
    res = requests.post(ziggu_url, data=data, verify=False)
    if issubclass(type(res), HTTPClientError):
        pyr_res = Response(body=res.content)
        for cookie in res.cookies:
            pyr_res.set_cookie(name=cookie.name, value=cookie.value)
        return pyr_res
    else:
        return HTTPUnauthorized(body=res.content)


def sign_in_external(request, data):
    if data['provider_name'] == 'openid':
        query_field = dict(id=data['user_name'])
    elif data['provider_name'] == 'github':
        query_field = dict()
    else:
        query_field = dict(username=data['user_name'])

    came_from = request.POST.get('came_from', '/')
    request.response.set_cookie('homepage_route', came_from)
    external_login_route = request.route_url('external_login', provider_name=data['provider_name'], _query=query_field)

    return HTTPFound(location=external_login_route, headers=request.response.headers)


@view_config(route_name='signin', request_method='POST', permission=NO_PERMISSION_REQUIRED)
def sign_in(request):
    provider_name = get_value_multiformat_post_checked(request, 'provider_name')
    user_name = get_value_multiformat_post_checked(request, 'user_name')
    password = get_multiformat_post(request, 'password')   # no check since password is None for external login

    verify_param(provider_name, paramCompare=providers, isIn=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `provider_name` not found within available providers",
                 content={u'provider_name': str(provider_name), u'providers': providers})

    if provider_name in internal_providers:
        return evaluate_call(lambda: sign_in_internal(request, {u'user_name': user_name, u'password': password}),
                             httpError=HTTPInternalServerError, content={u'provider': provider_name},
                             msgOnFail="Error occurred while signing in with internal provider")

    elif provider_name in external_providers:
        return evaluate_call(lambda: sign_in_external(request, {u'user_name': user_name,
                                                                u'password': password,
                                                                u'provider_name': provider_name}),
                             httpError=HTTPInternalServerError, content={u'provider': provider_name},
                             msgOnFail="Error occurred while signing in with external provider")


@view_config(route_name='signout', request_method='GET', permission=NO_PERMISSION_REQUIRED)
def sign_out(request):
    return HTTPTemporaryRedirect(location=request.route_url('ziggurat.routes.sign_out'))


@view_config(context=ZigguratSignInSuccess, permission=NO_PERMISSION_REQUIRED)
def login_success_ziggu(request):
    return valid_http(httpSuccess=HTTPOk, detail="Login successful",
                      httpKWArgs={'location': request.route_url('home'),
                                  'headers': request.context.headers})


def new_user_external(external_user_name, external_id, email, provider_name, db_session):
    """create new user with an External Identity"""
    local_user_name = external_user_name + '_' + provider_name
    local_user_name = local_user_name.replace(" ", '_')
    create_user(local_user_name, password=None, email=email, group_name=USER_GROUP, db_session=db_session)

    user = UserService.by_user_name(local_user_name, db_session=db_session)
    ex_identity = models.ExternalIdentity(external_user_name=external_user_name, external_id=external_id,
                                          local_user_id=user.id, provider_name=provider_name)
    evaluate_call(lambda: db_session.add(ex_identity), fallback=lambda: db_session.rollback(),
                  httpError=HTTPConflict, msgOnFail="Add external user refused by db",
                  content={u'provider_name': str(provider_name), u'local_user_name': str(local_user_name)})
    user.external_identities.append(ex_identity)
    return user


def login_success_external(request, external_user_name, external_id, email, provider_name):
    # find user by external_id = login_id
    # replace user from mongodb by user ziggurat and connect to externalId
    user = ExternalIdentityService.user_by_external_id_and_provider(external_id, provider_name, request.db)
    if user is None:
        # create new user with an External Identity
        user = new_user_external(external_user_name=external_user_name, external_id=external_id,
                                 email=email, provider_name=provider_name, db_session=request.db)
    # set a header to remember (set-cookie) -> this is the important line
    headers = remember(request, user.id)
    # If redirection given
    if 'homepage_route' in request.cookies:
        return HTTPFound(location=request.cookies['homepage_route'], headers=headers)
    else:
        return HTTPOk()


@view_config(context=ZigguratSignInBadAuth, permission=NO_PERMISSION_REQUIRED)
def login_failure(request, reason='not specified'):
    raise_http(httpError=HTTPBadRequest, detail="Login failure", content={u'reason': str(reason)})


@view_config(route_name='successful_operation')
def successful_operation(request):
    return valid_http(httpSuccess=HTTPOk, detail="Successful operation")


@view_config(context=ZigguratSignOut, permission=NO_PERMISSION_REQUIRED)
def sign_out_ziggu(request):
    return HTTPFound(location=request.route_url('successful_operation'),
                     headers=request.context.headers)


@view_config(route_name='external_login', permission=NO_PERMISSION_REQUIRED)
def authomatic_login(request):
    _authomatic = authomatic(request)
    open_id_provider_name = request.matchdict.get('provider_name')

    # Start the login procedure.

    response = Response()
    result = _authomatic.login(WebObAdapter(request, response), open_id_provider_name)

    if result:
        if result.error:
            # Login procedure finished with an error.
            return login_failure(request, reason=result.error.message)
        elif result.user:
            if not (result.user.name and result.user.id):
                result.user.update()
            # Hooray, we have the user!
            if result.provider.name in ['openid', 'dkrz', 'ipsl', 'smhi', 'badc', 'pcmdi']:
                # TODO: change login_id ... more infos ...
                return login_success_external(request,
                                              external_id=result.user.id,
                                              email=result.user.email,
                                              provider_name=result.provider.name,
                                              external_user_name=result.user.name)
            elif result.provider.name == 'github':
                # TODO: fix email ... get more infos ... which login_id?
                login_id = "{0.username}@github.com".format(result.user)
                # email = "{0.username}@github.com".format(result.user)
                # get extra info
                if result.user.credentials:
                    pass
                return login_success_external(request,
                                              external_id=login_id,
                                              email=login_id,
                                              provider_name=result.provider.name,
                                              external_user_name=result.user.name)

    return response


@view_config(route_name='session', permission=NO_PERMISSION_REQUIRED)
def get_session(request):
    def _get_session(req):
        authn_policy = req.registry.queryUtility(IAuthenticationPolicy)
        principals = authn_policy.effective_principals(req)
        if Authenticated in principals:
            user = request.user
            json_resp = {u'authenticated': True,
                         u'user_name': user.user_name,
                         u'user_email': user.email,
                         u'group_names': [group.group_name for group in user.groups]}
        else:
            json_resp = {u'authenticated': False}
        return json_resp

    session_json = evaluate_call(lambda: _get_session(request), httpError=HTTPInternalServerError,
                                 msgOnFail="Failed to get session details")
    return valid_http(httpSuccess=HTTPOk, detail="Get session successful", content=session_json)


@view_config(route_name='providers', request_method='GET')
def get_providers(request):
    return valid_http(httpSuccess=HTTPOk, detail="Get providers successful",
                      content={u'provider_names': providers,
                               u'internal_providers': internal_providers,
                               u'external_providers': external_providers})
