import json

from authomatic.adapters import WebObAdapter
from pyramid.httpexceptions import HTTPFound, HTTPOk, HTTPTemporaryRedirect, HTTPBadRequest
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
import requests
import models

from magpie import *
from management.user.user import create_user


external_provider = ['openid',
                     'dkrz',
                     'ipsl',
                     'badc',
                     'pcmdi',
                     'smhi',
                     'github']


@view_config(route_name='signin', request_method='POST', permission=NO_PERMISSION_REQUIRED)
def sign_in(request):
    provider_name = get_multiformat_post(request, 'provider_name')
    user_name = get_multiformat_post(request, 'user_name')
    password = get_multiformat_post(request, 'password')

    if provider_name == 'ziggurat':
        # redirection to ziggurat sign in
        data_to_send = {'user_name': user_name,
                        'password': password}
        #return HTTPTemporaryRedirect(location=request.route_url('ziggurat.routes.sign_in'))

        ziggu_url = request.route_url('ziggurat.routes.sign_in')
        res = requests.post(ziggu_url, data=data_to_send)
        if res.status_code < 400:
            pyr_res = Response(body=res.content)
            for cookie in res.cookies:
                pyr_res.set_cookie(name=cookie.name, value=cookie.value)
            return pyr_res
        else:
            return HTTPUnauthorized(body=res.content)

    elif provider_name in external_provider:
        if provider_name == 'openid':
            query_field = dict(id=user_name)
        else:
            query_field = dict(username=user_name)
        query_field['came_from'] = get_multiformat_post(request, 'came_from')
        external_login_route = request.route_url('external_login', provider_name=provider_name, _query=query_field)

        return HTTPFound(location=external_login_route)

    return HTTPBadRequest(detail='Bad provider name')


@view_config(route_name='signout', request_method='GET', permission=NO_PERMISSION_REQUIRED)
def sign_out(request):
    return HTTPTemporaryRedirect(location=request.route_url('ziggurat.routes.sign_out'))


@view_config(context=ZigguratSignInSuccess, permission=NO_PERMISSION_REQUIRED)
def login_success_ziggu(request):
    #return HTTPFound(location=request.route_url('successful_operation'),
    #                 headers=request.context.headers)
    return HTTPOk(detail='login success', headers=request.context.headers)



def login_success_external(request, external_user_name, external_id, email, providername):

    # find user by external_id = login_id
    # replace user from mongodb by user ziggurat and connect to externalId
    db = request.db
    user = ExternalIdentityService.user_by_external_id_and_provider(external_id, providername, db)
    if user is None:
        # create new user with an External Identity
        local_user_name = external_user_name+'_'+providername
        local_user_name = local_user_name.replace(" ", '_')
        create_user(local_user_name, password=None, email=email, group_name=USER_GROUP, db_session=db)

        try:
            user = UserService.by_user_name(local_user_name, db_session=db)
            ex_identity = models.ExternalIdentity(external_id=external_id,
                                                  local_user_id=user.id,
                                                  provider_name=providername,
                                                  external_user_name=external_user_name)

            db.add(ex_identity)
            user.external_identities.append(ex_identity)
            db.commit()
        except Exception, e:
            db.rollback()
            HTTPConflict(detail=e.message)

    # set a header to remember (set-cookie) -> this is the important line
    headers = remember(request, user.id)

    return HTTPFound(location=request.cookies['homepage_route'], headers=headers)



@view_config(context=ZigguratSignInBadAuth, permission=NO_PERMISSION_REQUIRED)
def login_failure(request, message='login failure'):
    #came_from_path = request.cookies['homepage_route']

    return HTTPBadRequest(detail=message)


@view_config(route_name='successful_operation')
def successful_operation(request):
    return HTTPOk()


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
            return login_failure(request, message=result.error.message)
        elif result.user:
            if not (result.user.name and result.user.id):
                result.user.update()
            # Hooray, we have the user!
            if result.provider.name in ['openid', 'dkrz', 'ipsl', 'smhi', 'badc', 'pcmdi']:
                # TODO: change login_id ... more infos ...
                return login_success_external(request,
                                     external_id=result.user.id,
                                          email=result.user.email,
                                          providername=result.provider.name,
                                          external_user_name=result.user.name)
            elif result.provider.name == 'github':
                # TODO: fix email ... get more infos ... which login_id?
                login_id = "{0.username}@github.com".format(result.user)
                #email = "{0.username}@github.com".format(result.user)
                # get extra info
                if result.user.credentials:
                    pass
                return login_success_external(login_id=login_id, name=result.user.name)
    else:
        came_from = request.GET.get('came_from', '/')
        response.set_cookie('homepage_route', came_from)
    return response


@view_config(route_name='session', permission=NO_PERMISSION_REQUIRED)
def get_session(request):
    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
    principals = authn_policy.effective_principals(request)
    if Authenticated in principals:
        user = request.user
        json_response = {'authenticated': True,
                         'user_name': user.user_name,
                         'user_email': user.email,
                         'group_names': [group.group_name for group in user.groups]}
    else:
        json_response = {'authenticated': False}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )

@view_config(route_name='providers', request_method='GET')
def get_providers(request):
    provider_names = ['ziggurat', 'dkrz', 'ipsl', 'badc', 'pcmdi', 'smhi']
    return HTTPOk(
        body=json.dumps({'provider_names': provider_names}),
        content_type='application/json'
    )





