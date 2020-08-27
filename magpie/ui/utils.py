import json
from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPInternalServerError, exception_response
from pyramid.request import Request

from magpie import __meta__
from magpie.api.generic import get_exception_info, get_request_info
from magpie.api.requests import get_logged_user
from magpie.constants import get_constant
from magpie.utils import CONTENT_TYPE_JSON, get_header, get_logger, get_magpie_url

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import (  # noqa: F401
        Any, AnyResponseType, CookiesType, Dict, HeadersType, JSON, Optional, Str, Union
    )

LOGGER = get_logger(__name__)


def check_response(response):
    # type: (AnyResponseType) -> AnyResponseType
    """
    :returns: response if the HTTP status code is successful.
    :raises HTTPError: (of appropriate type) if the response corresponds to an HTTP error code
    """
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response


def request_api(request,            # type: Request
                path,               # type: Str
                method="GET",       # type: Str
                data=None,          # type: Optional[Union[JSON, Str]]
                headers=None,       # type: Optional[HeadersType]
                cookies=None,       # type: Optional[CookiesType]
                ):                  # type: (...) -> AnyResponseType
    """
    Use a pyramid sub-request to request Magpie API routes via the UI. This avoids max retries and closed connections
    when using 1 worker (eg: during tests).

    Some information is retrieved from :paramref:`request` to pass down to the sub-request (eg: cookies).
    If they are passed as argument, corresponding values will override the ones found in :paramref:`request`.

    All sub-requests to the API are assumed to be :py:data:`magpie.common.CONTENT_TYPE_JSON` unless explicitly
    overridden with :paramref:`headers`. Headers are also looked for for additional ``Set-Cookie`` header in case they
    need to be passed down to :paramref:`cookies`.

    :param request: incoming Magpie UI request that requires sub-request to Magpie API, to retrieve required details.
    :param path: local Magpie API path (relative to root without URL).
    :param method: HTTP method to send the API sub-request.
    :param data: JSON dictionary or literal string content of the request body.
    :param headers: override headers to employ for the API sub-request. Defaults to JSON Accept & Content-Type headers.
    :param cookies: override cookies to employ for the API sub-request. Defaults to current logged user.
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
        data = ""
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


def redirect_error(request, code=None, content=None):
    # type: (Request, int, Optional[JSON]) -> AnyResponseType
    """Redirects the contents to be rendered by the UI 'error' page.

    :param request: incoming request that resulted into some kind of error.
    :param code: explicit HTTP status code for the error response, extracted from contents if otherwise available.
    :param content: any body content provided as error response from the API.
    """
    path = request.route_path("error")
    path = path.replace("/magpie/", "/") if path.startswith("/magpie") else path  # avoid glob other 'magpie'
    data = {"error_request": content, "error_code": code or content.get("code", 500)}
    return request_api(request, path, "POST", data)  # noqa


def handle_errors(func):
    """
    Decorator that encapsulates the operation in a try/except block, and
    redirects the response to the UI error page with API error contents.

    In worst case scenario where the operation cannot figure out what to do with the exception response,
    raise the most basic :class:`HTTPInternalServerError` that can be formulated from available details.

    .. seealso::
        :func:`redirect_error`
    """
    def wrap(*args, **kwargs):
        view_container = None if not args and not isinstance(args[0], BaseViews) else args[0]
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            detail = "{}: {}".format(type(exc).__name__, str(exc))
            exc_info = get_exception_info(exc, exception_details=True) or detail  # noqa
            LOGGER.error("Unexpected API error under UI operation. [%s]", exc_info)
            content = {}
            if view_container:
                content = get_request_info(view_container.request, default_message=detail, exception_details=True)
            if isinstance(exc_info, dict) and "exception" in exc_info and "exception" not in content:
                content = exc_info
            if "detail" not in content:
                content = {"detail": detail}
            if view_container:
                return redirect_error(view_container.request, content=content)
            raise HTTPInternalServerError(detail=str(exc))
    return wrap


class BaseViews(object):
    """Base methods for Magpie UI pages."""
    MAGPIE_FIXED_GROUP_MEMBERSHIPS = []
    MAGPIE_FIXED_GROUP_EDITS = []

    def __init__(self, request):
        self.request = request
        self.magpie_url = get_magpie_url(self.request)
        self.ui_theme = get_constant("MAGPIE_UI_THEME", self.request)
        self.logged_user = get_logged_user(self.request)

        anonymous = get_constant("MAGPIE_ANONYMOUS_GROUP", settings_container=self.request)
        admin = get_constant("MAGPIE_ADMIN_GROUP", settings_container=self.request)
        self.__class__.MAGPIE_FIXED_GROUP_MEMBERSHIPS = [anonymous]   # special groups membership that cannot be edited
        self.__class__.MAGPIE_FIXED_GROUP_EDITS = [anonymous, admin]  # special groups that cannot be edited

    def add_template_data(self, data=None):
        # type: (Optional[Dict[Str, Any]]) -> Dict[Str, Any]
        """Adds required template data for the 'heading' mako template applied to every UI page."""
        all_data = data or {}
        all_data.update({
            "MAGPIE_TITLE": __meta__.__title__,
            "MAGPIE_AUTHOR": __meta__.__author__,
            "MAGPIE_VERSION": __meta__.__version__,
            "MAGPIE_SOURCE_URL": __meta__.__url__,
            "MAGPIE_DESCRIPTION": __meta__.__description__,
        })
        all_data.setdefault("MAGPIE_SUB_TITLE", "Administration")
        all_data.setdefault("MAGPIE_UI_THEME", self.ui_theme)
        all_data.setdefault("MAGPIE_FIXED_GROUP_MEMBERSHIPS", self.MAGPIE_FIXED_GROUP_MEMBERSHIPS)
        all_data.setdefault("MAGPIE_FIXED_GROUP_EDITS", self.MAGPIE_FIXED_GROUP_EDITS)
        magpie_logged_user = get_logged_user(self.request)
        if magpie_logged_user:
            all_data.update({"MAGPIE_LOGGED_USER": magpie_logged_user.user_name})
        return all_data
