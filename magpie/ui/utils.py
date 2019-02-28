from magpie.definitions.pyramid_definitions import exception_response, Request, Response, HTTPBadRequest
from magpie.common import get_header, JSON_TYPE
from typing import TYPE_CHECKING
import json
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Str, JsonBody, CookiesType, HeadersType, Optional


def check_response(response):
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response


def request_api(request,            # type: Request
                path,               # type: Str
                method='GET',       # type: Optional[Str]
                data=None,          # type: Optional[JsonBody]
                headers=None,       # type: Optional[HeadersType]
                cookies=None,       # type: Optional[CookiesType]
                ):                  # type: (...) -> Response
    """
    Use a pyramid sub-request to request Magpie API routes via the UI.
    This avoids max retries and closed connections when using 1 worker (eg: during tests).

    Some information is retrieved from ``request`` to pass down to the sub-request (eg: headers, cookies).
    If they are passed as argument, corresponding values will override the ones found in ``request``.
    All sub-requests to the API are assumed to be of ``magpie.common.JSON_TYPE``.
    """
    method = method.upper()
    extra_kwargs = {'method': method}

    if headers:
        headers = dict(headers)
    if not headers and not request.headers:
        headers = {'Accept': JSON_TYPE, 'Content-Type': JSON_TYPE}
    if not headers:
        headers = request.headers
    # although no body is required per-say for HEAD/GET requests, add it if missing
    # this avoid downstream errors when 'request.POST' is accessed
    # we use a plain empty byte str because `{}` or `None` cause errors on each case
    # of local/remote testing with corresponding `webtest.TestApp`/`requests.Request`
    if not data:
        data = u''
    if isinstance(data, dict) and get_header('Content-Type', headers, split=[',', ';']) == JSON_TYPE:
        data = json.dumps(data)

    if isinstance(cookies, dict):
        cookies = list(cookies.items())
    if cookies and isinstance(headers, dict):
        headers = list(cookies.items())
        for c, v in cookies:
            headers.append(('Set-Cookie', '{}={}'.format(c, v)))
    if not cookies:
        cookies = request.cookies
    # cookies must be added to kw only if populated, iterable error otherwise
    if cookies:
        extra_kwargs['cookies'] = cookies

    subreq = Request.blank(path, base_url=request.application_url, headers=headers, POST=data, **extra_kwargs)
    return request.invoke_subrequest(subreq)


def error_badrequest(func):
    """Decorator that encapsulates the operation in a try/except block, and returns HTTP Bad Request on exception."""
    def wrap(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise HTTPBadRequest(detail=str(e))
    return wrap
