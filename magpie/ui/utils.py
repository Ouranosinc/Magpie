from magpie.definitions.pyramid_definitions import exception_response
from magpie.definitions.typedefs import AnyStr, JsonBody, Cookies, Headers, Optional
from pyramid.request import Request
from pyramid.response import Response


def check_response(response):
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response


def request_api(request,            # type: Request
                path,               # type: AnyStr
                method='GET',       # type: Optional[AnyStr]
                data=None,          # type: Optional[JsonBody]
                headers=None,       # type: Optional[Headers]
                cookies=None,       # type: Optional[Cookies]
                ):                  # type: (...) -> Response
    """
    Use a pyramid sub-request to request Magpie API routes via the UI.
    This avoids max retries and closed connections when using 1 worker (eg: during tests).

    Some information is retrieved from :param:`request` to pass down to the sub-request (eg: headers, cookies).
    If they are passed as argument, corresponding values will override the ones found in :param:`request`.
    All sub-requests to the API are assumed to be of JSON type.
    """
    method = method.upper()
    extra_kwargs = {'method': method}

    if headers:
        headers = dict(headers)
    if not headers and not request.headers:
        headers = {'Accept': 'application/json'}
    if not headers:
        headers = request.headers
    if not data and method not in ('HEAD', 'GET'):
        data = {}

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
