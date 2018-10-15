from authomatic.adapters import WebObAdapter
from authomatic.providers import oauth1, oauth2, openid
from authomatic import Authomatic, provider_id
from magpie.security import authomatic_config, authomatic_setup, get_provider_names
from magpie.constants import get_constant
from magpie.definitions.ziggurat_definitions import *
from magpie.api.api_except import *
from magpie.api.api_requests import *
from magpie.api.api_rest_schemas import *
from magpie.api.management.user.user_formats import *
from magpie.api.management.user.user_utils import create_user
import requests


# dictionaries of {'provider_id': 'provider_display_name'}
default_provider = get_constant('MAGPIE_DEFAULT_PROVIDER')
MAGPIE_INTERNAL_PROVIDERS = {default_provider: default_provider.capitalize()}
MAGPIE_EXTERNAL_PROVIDERS = get_provider_names()
MAGPIE_PROVIDER_KEYS = MAGPIE_INTERNAL_PROVIDERS.keys() + MAGPIE_EXTERNAL_PROVIDERS.keys()


def process_sign_in_external(request, username, provider):
    provider_name = provider.lower()
    if provider_name == 'openid':
        query_field = dict(id=username)
    elif provider_name == 'github':
        query_field = dict(login_field=username)
    else:
        query_field = dict(username=username)

    came_from = request.POST.get('came_from', '/')
    request.response.set_cookie('homepage_route', came_from)
    external_login_route = request.route_url(ProviderSigninAPI.name, provider_name=provider_name, _query=query_field)
    #external_login_route = request.route_url(ProviderSigninAPI.name, provider_name=provider_name)

    #resp = requests.get(external_login_route, headers={'redirect_uri': request.application_url}, allow_redirects=True)
    #return HTTPFound(resp.request.application_url, headers=resp.request.headers)
    #return HTTPFound(location=external_login_route, headers=resp.headers)

    #subreq = request.copy()
    #subreq.path_info = external_login_route
    #try:
    #    resp = request.invoke_subrequest(subreq)
    #except Exception as ex:
    #    print(ex)

    return HTTPFound(location=external_login_route, headers=request.response.headers)


def verify_provider(provider_name):
    verify_param(provider_name, paramName=u'provider_name', paramCompare=MAGPIE_PROVIDER_KEYS, isIn=True,
                 httpError=HTTPNotFound, msgOnFail=ProviderSignin_GET_NotFoundResponseSchema.description)


@view_config(route_name='signin_external', request_method='POST', permission=NO_PERMISSION_REQUIRED)
def sign_in_external(request):
    provider_name = get_value_multiformat_post_checked(request, 'provider_name')
    user_name = get_value_multiformat_post_checked(request, 'user_name')
    verify_provider(provider_name)
    return process_sign_in_external(request, user_name, provider_name)


@SigninAPI.post(schema=Signin_POST_RequestSchema(), tags=[LoginTag], response_schemas=Signin_POST_responses)
@view_config(route_name=SigninAPI.name, request_method='POST', permission=NO_PERMISSION_REQUIRED)
def sign_in(request):
    """Signs in a user session."""
    provider_name = get_value_multiformat_post_checked(request, 'provider_name', default=default_provider).lower()
    user_name = get_value_multiformat_post_checked(request, 'user_name')
    password = get_multiformat_post(request, 'password')   # no check since password is None for external login
    verify_provider(provider_name)

    if provider_name in MAGPIE_INTERNAL_PROVIDERS.keys():
        signin_internal_url = '{host}{path}'.format(host=request.application_url, path='/signin_internal')
        signin_internal_data = {u'user_name': user_name, u'password': password, u'provider_name': provider_name}
        signin_response = requests.post(signin_internal_url, data=signin_internal_data, allow_redirects=True)

        if signin_response.status_code == HTTPOk.code:
            pyramid_response = Response(body=signin_response.content, headers=signin_response.headers)
            for cookie in signin_response.cookies:
                pyramid_response.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
            return pyramid_response
        login_failure(request)

    elif provider_name in MAGPIE_EXTERNAL_PROVIDERS.keys():
        return evaluate_call(lambda: process_sign_in_external(request, user_name, provider_name),
                             httpError=HTTPInternalServerError,
                             content={u'user_name': user_name,  u'provider_name': provider_name},
                             msgOnFail=Signin_POST_InternalServerErrorResponseSchema.description)


# swagger responses referred in `sign_in`
@view_config(context=ZigguratSignInSuccess, permission=NO_PERMISSION_REQUIRED)
def login_success_ziggurat(request):
    # headers contains login authorization cookie
    return valid_http(httpSuccess=HTTPOk, httpKWArgs={'headers': request.context.headers},
                      detail=Signin_POST_OkResponseSchema.description, )


# swagger responses referred in `sign_in`
@view_config(context=ZigguratSignInBadAuth, permission=NO_PERMISSION_REQUIRED)
def login_failure(request, reason=None):
    httpError = HTTPUnauthorized
    if reason is None:
        httpError = HTTPNotAcceptable
        reason = Signin_POST_NotAcceptableResponseSchema.description
        user_name = request.POST.get('user_name')
        if user_name is None:
            httpError = HTTPBadRequest
            reason = Signin_POST_BadRequestResponseSchema.description
        else:
            user_name_list = evaluate_call(lambda: [user.user_name for user in models.User.all(db_session=request.db)],
                                           fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                                           msgOnFail=Signin_POST_ForbiddenResponseSchema.description)
            if user_name in user_name_list:
                httpError = HTTPUnauthorized
                reason = "Incorrect credentials."
    raise_http(httpError=httpError, content={u'reason': str(reason)},
               detail=Signin_POST_UnauthorizedResponseSchema.description)


def new_user_external(external_user_name, external_id, email, provider_name, db_session):
    """Create new user with an External Identity"""
    internal_user_name = external_user_name + '_' + provider_name
    internal_user_name = internal_user_name.replace(" ", '_')
    group_name = get_constant('MAGPIE_USERS_GROUP')
    create_user(internal_user_name, password=None, email=email, group_name=group_name, db_session=db_session)

    user = UserService.by_user_name(internal_user_name, db_session=db_session)
    ex_identity = models.ExternalIdentity(external_user_name=external_user_name, external_id=external_id,
                                          local_user_id=user.id, provider_name=provider_name)
    evaluate_call(lambda: db_session.add(ex_identity), fallback=lambda: db_session.rollback(),
                  httpError=HTTPConflict, msgOnFail=Signin_POST_ConflictResponseSchema.description,
                  content={u'provider_name': str(provider_name),
                           u'internal_user_name': str(internal_user_name),
                           u'external_user_name': str(external_user_name),
                           u'external_id': str(external_id)})
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

    homepage_route = '/' if 'homepage_route' not in request.cookies else str(request.cookies['homepage_route'])
    #resp = HTTPFound(location='localhost:2001/magpie', headers=headers)
    #resp.set_cookie('came_from', 'localhost:2001/magpie')
    #return resp
    return valid_http(httpSuccess=HTTPFound, detail="External login homepage route found.",
                      content={u'homepage_route': homepage_route},
                      httpKWArgs={'location': homepage_route, 'headers': headers})


@ProviderSigninAPI.get(tags=[LoginTag], response_schemas=ProviderSignin_GET_responses)
@view_config(route_name=ProviderSigninAPI.name, permission=NO_PERMISSION_REQUIRED)
def authomatic_login(request):
    """Signs in a user session using an external provider."""
    #_authomatic = authomatic(request)
    provider_name = request.matchdict.get('provider_name')
    verify_provider(provider_name)

    # Start the login procedure
    response = Response()
    external_providers_authomatic = authomatic_setup(request)
    result = external_providers_authomatic.login(WebObAdapter(request, response), provider_name)

    if result:
        if result.error:
            # Login procedure finished with an error.
            return login_failure(request, reason=result.error.message)
        elif result.user:
            if not (result.user.name and result.user.id):
                result.user.update()
            provider_name = result.provider.name.lower()
            # Hooray, we have the user!
            if provider_name in ['openid', 'dkrz', 'ipsl', 'smhi', 'badc', 'pcmdi']:
                # TODO: change login_id ... more infos ...
                return login_success_external(request,
                                              external_id=result.user.id,
                                              email=result.user.email,
                                              provider_name=result.provider.name,
                                              external_user_name=result.user.name)
            elif provider_name == 'github':
                # TODO: fix email ... get more infos ... which login_id?
                login_id = "{0.username}@github.com".format(result.user)
                # email = "{0.username}@github.com".format(result.user)
                # get extra info
                if result.user.credentials:
                    pass
                return login_success_external(request,
                                              external_id=login_id,
                                              email=result.user.email,
                                              provider_name=result.provider.name,
                                              external_user_name=result.user.name)

    return response


@SignoutAPI.get(tags=[LoginTag], response_schemas=Signout_GET_responses)
@view_config(context=ZigguratSignOut, permission=NO_PERMISSION_REQUIRED)
def sign_out(request):
    """Signs out the current user session."""
    return valid_http(httpSuccess=HTTPOk, httpKWArgs={'headers': forget(request)},
                      detail=Signout_GET_OkResponseSchema.description)


@SessionAPI.get(tags=[LoginTag], response_schemas=Session_GET_responses)
@view_config(route_name=SessionAPI.name, permission=NO_PERMISSION_REQUIRED)
def get_session(request):
    """Get information about current session."""
    def _get_session(req):
        authn_policy = req.registry.queryUtility(IAuthenticationPolicy)
        principals = authn_policy.effective_principals(req)
        if Authenticated in principals:
            user = request.user
            json_resp = {u'authenticated': True, u'user': format_user(user)}
        else:
            json_resp = {u'authenticated': False}
        return json_resp

    session_json = evaluate_call(lambda: _get_session(request), httpError=HTTPInternalServerError,
                                 msgOnFail=Session_GET_InternalServerErrorResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, detail=Session_GET_OkResponseSchema.description, content=session_json)


@ProvidersAPI.get(tags=[LoginTag], response_schemas=Providers_GET_responses)
@view_config(route_name=ProvidersAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_providers(request):
    """Get list of login providers."""
    return valid_http(httpSuccess=HTTPOk, detail=Providers_GET_OkResponseSchema.description,
                      content={u'providers': {u'internal': sorted(MAGPIE_INTERNAL_PROVIDERS.values()),
                                              u'external': sorted(MAGPIE_EXTERNAL_PROVIDERS.values()), }})
