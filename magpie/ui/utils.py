import json
from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPBadRequest, exception_response
from pyramid.request import Request

from magpie.api.requests import get_logged_user
from magpie.utils import CONTENT_TYPE_JSON, get_header, get_logger, get_magpie_url

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import Any, CookiesType, Dict, HeadersType, JSON, Optional, Str  # noqa: F401
    from pyramid.response import Response

LOGGER = get_logger(__name__)


def check_response(response):
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response


def request_api(request,            # type: Request
                path,               # type: Str
                method="GET",       # type: Str
                data=None,          # type: Optional[JSON]
                headers=None,       # type: Optional[HeadersType]
                cookies=None,       # type: Optional[CookiesType]
                ):                  # type: (...) -> Response
    """
    Use a pyramid sub-request to request Magpie API routes via the UI. This avoids max retries and closed connections
    when using 1 worker (eg: during tests).

    Some information is retrieved from ``request`` to pass down to the sub-request (eg: cookies).
    If they are passed as argument, corresponding values will override the ones found in ``request``.

    All sub-requests to the API are assumed to be of ``magpie.common.CONTENT_TYPE_JSON`` unless explicitly overridden
    with ``headers``.
    """
    method = method.upper()
    extra_kwargs = {"method": method}

    if headers:
        headers = dict(headers)
    else:
        headers = {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON}
    # although no body is required per-say for HEAD/GET requests, add it if missing
    # this avoid downstream errors when 'request.POST' is accessed
    # we use a plain empty byte str because empty dict `{}` or `None` cause errors on each case
    # of local/remote testing with corresponding `webtest.TestApp`/`requests.Request`
    if not data:
        data = u""
    if isinstance(data, dict) and get_header("Content-Type", headers, split=[",", ";"]) == CONTENT_TYPE_JSON:
        data = json.dumps(data)

    if isinstance(cookies, dict):
        cookies = list(cookies.items())
    if cookies and isinstance(headers, dict):
        headers = list(headers.items())
        for cookie_name, cookie_value in cookies:
            headers.append(("Set-Cookie", "{}={}".format(cookie_name, cookie_value)))
    if not cookies:
        cookies = request.cookies
    # cookies must be added to kw only if populated, iterable error otherwise
    if cookies:
        extra_kwargs["cookies"] = cookies

    subreq = Request.blank(path, base_url=request.application_url, headers=headers, POST=data, **extra_kwargs)
    return request.invoke_subrequest(subreq, use_tweens=True)


def error_badrequest(func):
    """
    Decorator that encapsulates the operation in a try/except block, and returns HTTP Bad Request on exception.
    """
    def wrap(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            raise HTTPBadRequest(detail=str(exc))
    return wrap


class BaseViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = get_magpie_url(request.registry)
        self.logged_user = get_logged_user(request)

    def add_template_data(self, data=None):
        # type: (Optional[Dict[Str, Any]]) -> Dict[Str, Any]
        """Adds required template data for the 'heading' mako template applied to every UI page."""
        all_data = data or {}
        all_data.setdefault("MAGPIE_SUB_TITLE", "Administration")
        magpie_logged_user = get_logged_user(self.request)
        if magpie_logged_user:
            all_data.update({"MAGPIE_LOGGED_USER": magpie_logged_user.user_name})
        return all_data
