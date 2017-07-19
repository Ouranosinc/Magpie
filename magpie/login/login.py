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

from security import authomatic
import models

external_provider = ['openid',
                     'dkrz',
                     'ipsl',
                     'badc',
                     'pcmdi',
                     'smhi']


@view_config(route_name='signin')
def sign_in(request):
    provider_name = request.POST.get('provider_name')
    user_name = request.POST.get('user_name')
    if provider_name == 'ziggurat':
        # redirection to ziggurat sign in
        return HTTPTemporaryRedirect(location=request.route_url('ziggurat.routes.sign_in'))
    elif provider_name in external_provider:
        user_name_field = {'username': user_name}
        external_login_route = request.route_url('external_login', provider_name=provider_name, _query=user_name_field)
        return HTTPTemporaryRedirect(location=external_login_route)

    return HTTPBadRequest(detail='Bad provider name')


@view_config(route_name='signout')
def sign_out(request):
    return HTTPTemporaryRedirect(location=request.route_url('ziggurat.routes.sign_out'))


@view_config(context=ZigguratSignInSuccess, permission=NO_PERMISSION_REQUIRED)
def login_success_ziggu(request):
    came_from_path = request.POST.get('came_from')
    user = request.user
    return HTTPFound(location=came_from_path,
                     headers=request.context.headers)


def login_success_external(request, username, external_id, email, providername):

    # find user by external_id = login_id
    # replace user from mongodb by user ziggurat and connect to externalId
    db = request.db
    user = ExternalIdentityService.user_by_external_id_and_provider(external_id, providername, db)
    if user is None:
        # create new user with an External Identity
        user = models.User(user_name=username, email=email)
        user.regenerate_security_code()

        db.add(user)
        db.commit()

        group = GroupService.by_group_name('user', db)
        group_entry = models.UserGroup(group_id=group.id, user_id=user.id)
        db.add(group_entry)
        db.commit()

        ex_identity = models.ExternalIdentity(external_id=external_id,
                                              local_user_id=user.id,
                                              provider_name=providername,
                                              external_user_name=username)

        db.add(ex_identity)
        user.external_identities.append(ex_identity)
        db.commit()

    # set a header to remember (set-cookie) -> this is the important line
    headers = remember(request, user.id)
    return HTTPFound(location=request.cookies['homepage_route'], headers=headers)


@view_config(context=ZigguratSignInBadAuth, permission=NO_PERMISSION_REQUIRED)
def login_failure(request, message=''):
    came_from_path = request.cookies['homepage_route']
    return HTTPFound(location=came_from_path, detail=message)


@view_config(context=ZigguratSignOut, permission=NO_PERMISSION_REQUIRED)
def sign_out_ziggu(request):
    came_from_path = request.POST.get('came_from')
    return HTTPFound(location=came_from_path,
                     headers=request.context.headers)


@view_config(route_name='external_login')
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
                                          username=result.user.name)
            elif result.provider.name == 'github':
                # TODO: fix email ... get more infos ... which login_id?
                login_id = "{0.username}@github.com".format(result.user)
                #email = "{0.username}@github.com".format(result.user)
                # get extra info
                if result.user.credentials:
                    pass
                return login_success_external(login_id=login_id, name=result.user.name)
    else:
        came_from = request.POST.get('came_from')
        response.set_cookie('homepage_route', came_from)
    return response


@view_config(route_name='session')
def get_session(request):
    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
    principals = authn_policy.effective_principals(request)
    if Authenticated in principals:
        user = request.user
        json_response = {'authenticated': True,
                         'user_name': user.user_name}
    else:
        json_response = {'authenticated': False}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json')


