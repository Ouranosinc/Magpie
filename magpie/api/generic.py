from typing import TYPE_CHECKING

from pyramid.authentication import Authenticated, IAuthenticationPolicy
from pyramid.exceptions import PredicateMismatch
from pyramid.httpexceptions import (
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPMethodNotAllowed,
    HTTPNotAcceptable,
    HTTPNotFound,
    HTTPServerError,
    HTTPUnauthorized
)
from simplejson import JSONDecodeError

from magpie.api import schemas as s
from magpie.api.exception import raise_http, verify_param
from magpie.utils import (
    CONTENT_TYPE_ANY,
    CONTENT_TYPE_JSON,
    SUPPORTED_CONTENT_TYPES,
    get_header,
    get_logger,
    get_magpie_url
)

if TYPE_CHECKING:
    from typing import Callable
    from magpie.typedefs import Str, JSON  # noqa: F401
    from pyramid.registry import Registry
    from pyramid.request import Request
    from pyramid.response import Response
    from pyramid.httpexceptions import HTTPException
LOGGER = get_logger(__name__)


def internal_server_error(request):
    # type: (Request) -> HTTPException
    """
    Overrides default HTTP.
    """
    content = get_request_info(request, exception_details=True,
                               default_message=s.InternalServerErrorResponseSchema.description)
    return raise_http(nothrow=True, http_error=HTTPInternalServerError, detail=content[u"detail"], content=content,
                      content_type=get_header("Accept", request.headers, default=CONTENT_TYPE_JSON, split=";,"))


def not_found_or_method_not_allowed(request):
    # type: (Request) -> HTTPException
    """
    Overrides the default ``HTTPNotFound`` [404] by appropriate ``HTTPMethodNotAllowed`` [405] when applicable.

    Not found response can correspond to underlying process operation not finding a required item, or a completely
    unknown route (path did not match any existing API definition).
    Method not allowed is more specific to the case where the path matches an existing API route, but the specific
    request method (GET, POST, etc.) is not allowed on this path.

    Without this fix, both situations return [404] regardless.
    """
    if (isinstance(request.exception, PredicateMismatch)
        and request.method not in request.exception._safe_methods   # pylint: disable=W0212  # noqa: W0212
    ):
        http_err = HTTPMethodNotAllowed
        http_msg = ""   # auto-generated by HTTPMethodNotAllowed
    else:
        http_err = HTTPNotFound
        http_msg = s.NotFoundResponseSchema.description
    content = get_request_info(request, default_message=http_msg)
    return raise_http(nothrow=True, http_error=http_err, detail=content[u"detail"], content=content,
                      content_type=get_header("Accept", request.headers, default=CONTENT_TYPE_JSON, split=";,"))


def unauthorized_or_forbidden(request):
    # type: (Request) -> HTTPException
    """
    Overrides the default ``HTTPForbidden`` [403] by appropriate ``HTTPUnauthorized`` [401] when applicable.

    Unauthorized response is for restricted user access according to credentials and/or authorization headers.
    Forbidden response is for operation refused by the underlying process operations.

    Without this fix, both situations return [403] regardless.

    .. seealso::
        http://www.restapitutorial.com/httpstatuscodes.html
    """
    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
    http_err = HTTPForbidden
    http_msg = s.HTTPForbiddenResponseSchema.description
    if authn_policy:
        principals = authn_policy.effective_principals(request)
        if Authenticated not in principals:
            http_err = HTTPUnauthorized
            http_msg = s.UnauthorizedResponseSchema.description
    content = get_request_info(request, default_message=http_msg)

    return raise_http(nothrow=True, http_error=http_err, detail=content[u"detail"], content=content,
                      content_type=get_header("Accept", request.headers, default=CONTENT_TYPE_JSON, split=";,"))


def validate_accept_header_tween(handler, registry):    # noqa: F811
    # type: (Callable[[Request], Response], Registry) -> Callable[[Request], Response]
    """
    Tween that validates that the specified request ``Accept`` header (if any) is a supported one by the application.

    :raises HTTPNotAcceptable: if `Accept` header was specified and is not supported.
    """
    def validate_accept_header(request):
        # type: (Request) -> Response
        """
        Validates the specified request according to its ``Accept`` header, ignoring UI related routes that request
        more content-types than the ones supported by the application for display purposes (styles, images etc.).
        """
        # server URL could have more prefixes than only /magpie, so start by removing them using explicit URL setting
        # remove any additional hostname and known /magpie prefix to get only the final magpie-specific path
        magpie_url = get_magpie_url(request)
        magpie_url = request.url.replace(magpie_url, "")
        magpie_path = magpie_url.replace(request.host, "")
        magpie_path = magpie_path.split("/magpie")[-1]
        # ignore types defined under UI or static routes to allow rendering
        if not any(magpie_path.startswith(p) for p in ("/ui", "/static")):
            any_supported_header = SUPPORTED_CONTENT_TYPES + [CONTENT_TYPE_ANY]
            accept = get_header("accept", request.headers, default=CONTENT_TYPE_JSON, split=";,")
            verify_param(accept, is_in=True, param_compare=any_supported_header, param_name="Accept Header",
                         http_error=HTTPNotAcceptable, msg_on_fail=s.NotAcceptableResponseSchema.description)
        return handler(request)
    return validate_accept_header


def get_request_info(request, default_message=u"undefined", exception_details=False):
    # type: (Request, Str, bool) -> JSON
    """
    Obtains additional content details about the ``request`` according to available information.
    """
    content = {
        u"route_name": str(request.upath_info),
        u"request_url": str(request.url),
        u"detail": default_message,
        u"method": request.method
    }
    if hasattr(request, "exception"):
        # handle error raised simply by checking for "json" property in python 3 when body is invalid
        has_json = False
        try:
            has_json = hasattr(request.exception, "json")
        except JSONDecodeError:
            pass
        if has_json and isinstance(request.exception.json, dict):
            content.update(request.exception.json)
        elif isinstance(request.exception, HTTPServerError) and hasattr(request.exception, "message"):
            content.update({u"exception": str(request.exception.message)})
        elif isinstance(request.exception, Exception) and exception_details:
            content.update({u"exception": repr(request.exception)})
            # get 'request.exc_info' or 'sys.exc_info', whichever one is available
            LOGGER.error("Request exception.", exc_info=getattr(request, "exc_info", True))
        if not content[u"detail"]:
            content[u"detail"] = str(request.exception)
    elif hasattr(request, "matchdict"):
        if request.matchdict is not None and request.matchdict != "":
            content.update(request.matchdict)
    return content
