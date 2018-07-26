from magpie.definitions.pyramid_definitions import *
from magpie.api.api_except import *
from magpie.api.api_rest_schemas import *
from magpie import __meta__, db


@notfound_view_config()
def not_found(request):
    content = get_request_info(request, default_msg=NotFoundResponseSchema.description)
    return raise_http(nothrow=True, httpError=HTTPNotFound, contentType='application/json',
                      detail=content['detail'], content=content)


@exception_view_config()
def internal_server_error(request):
    content = get_request_info(request, default_msg=InternalServerErrorResponseSchema.description)
    return raise_http(nothrow=True, httpError=HTTPInternalServerError, contentType='application/json',
                      detail=content['detail'], content=content)


@forbidden_view_config()
def unauthorized_access(request):
    # if not overridden, default is HTTPForbidden [403], which is for a slightly different situation
    # this better reflects the HTTPUnauthorized [401] user access with specified AuthZ headers
    # [http://www.restapitutorial.com/httpstatuscodes.html]
    content = get_request_info(request, default_msg=UnauthorizedResponseSchema.description)
    return raise_http(nothrow=True, httpError=HTTPUnauthorized, contentType='application/json',
                      detail=content['detail'], content=content)


def get_request_info(request, default_msg="undefined"):
    content = {u'route_name': str(request.upath_info), u'request_url': str(request.url), u'detail': default_msg}
    if hasattr(request, 'exception'):
        if hasattr(request.exception, 'json'):
            if type(request.exception.json) is dict:
                content.update(request.exception.json)
        elif isinstance(request.exception, HTTPServerError) and hasattr(request.exception, 'message'):
            content.update({u'exception': str(request.exception.message)})
    elif hasattr(request, 'matchdict'):
        if request.matchdict is not None and request.matchdict != '':
            content.update(request.matchdict)
    return content
