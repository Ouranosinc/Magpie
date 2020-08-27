import json as json_pkg  # avoid conflict name with json argument employed for some function
import unittest
import warnings
from distutils.version import LooseVersion
from typing import TYPE_CHECKING

import pytest
import requests
import six
from pyramid.settings import asbool
from pyramid.testing import setUp as PyramidSetUp
from six.moves.urllib.parse import urlparse
from webtest import TestApp
from webtest.response import TestResponse

from magpie import __meta__, app, services
from magpie.constants import get_constant
from magpie.services import ServiceAccess
from magpie.utils import (
    CONTENT_TYPE_HTML,
    CONTENT_TYPE_JSON,
    SingletonMeta,
    get_header,
    get_magpie_url,
    get_settings_from_config_ini,
    is_magpie_ui_path
)

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from tests.interfaces import Base_Magpie_TestCase, User_Magpie_TestCase
    from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Type, Union
    from magpie.typedefs import (
        AnyCookiesType, AnyHeadersType, AnyResponseType, AnyValue, CookiesType, HeadersType, JSON, SettingsType, Str
    )
    # pylint: disable=C0103,invalid-name
    OptionalHeaderCookiesType = Tuple[Optional[AnyHeadersType], Optional[AnyCookiesType]]
    TestAppOrUrlType = Union[Str, TestApp]
    AnyMagpieTestCaseType = Union[Type[Base_Magpie_TestCase], Base_Magpie_TestCase,
                                  Type[User_Magpie_TestCase], User_Magpie_TestCase]
    AnyMagpieTestItemType = Union[AnyMagpieTestCaseType, TestAppOrUrlType]

OptionalStringType = six.string_types + tuple([type(None)])


class RunOption(object):
    __slots__ = ["_name", "_enabled", "_marker", "_description"]

    def __init__(self, name, marker=None, description=None):
        self._name = name
        self._marker = marker if marker else name.lower().replace("magpie_test_", "")
        self._enabled = self._default_run()
        self._description = description

    def __call__(self, *args, **kwargs):
        """
        Return (condition, reason) matching ``unittest.skipUnless`` decorator.
        """
        return self._enabled, self.message

    def __str__(self):
        return self.message

    def __repr__(self):
        return "{}[{}]".format(type(self).__name__, self.message)

    def _default_run(self):
        option_value = asbool(get_constant(self._name, default_value=True,
                                           raise_missing=False, raise_not_set=False, print_missing=True))
        return True if option_value is None else option_value

    @property
    def message(self):
        option = " '{}' ".format(self._marker)
        status = "Run" if self._enabled else "Skip"
        return "{}{}tests requested [{}={}].".format(status, option, self._name, self._enabled)

    @property
    def name(self):
        return self._name

    @property
    def enabled(self):
        return self._enabled

    @property
    def marker(self):
        return self._marker


def make_run_option_decorator(run_option):
    # type: (RunOption) -> Callable
    """
    Decorates (by default) the test/class with ``pytest.mark`` and ``unittest.skipUnless`` using the provided test
    condition represented by the specified :class:`RunOption`.

    Allows to decorate a function or class such that:

    .. code-block: python

        run_option = make_run_option_decorator(RunOption("MAGPIE_TEST_CUSTOM_MARKER"))

        @run_option
        def test_func():
            pass  # <tests>

    is equivalent to:

    .. code-block: python

        @pytest.mark.custom_marker
        @unittest.skipUnless(runner.MAGPIE_TEST_CUSTOM_MARKER, reason="...")
        def test_func():
            pass  # <tests>

    All ``<custom_marker>`` definitions should be added to ``setup.cfg`` to allow :mod:`pytest` to reference them.
    """
    def wrap(test_func, *args, **kwargs):  # noqa: F811
        pytest_marker = pytest.mark.__getattr__(run_option.marker)
        unittest_skip = unittest.skipUnless(*run_option())
        test_func = pytest_marker(test_func)
        test_func = unittest_skip(test_func)
        return test_func

    return wrap


class RunOptionDecorator(object):
    """
    Simplifies the call to::

        make_run_option_decorator(RunOption("MAGPIE_TEST_CUSTOM_MARKER"))

    by::

        RunOptionDecorator("MAGPIE_TEST_CUSTOM_MARKER")
    """
    def __new__(cls, name, description=None):
        return make_run_option_decorator(RunOption(name, description=description))


def config_setup_from_ini(config_ini_file_path):
    settings = get_settings_from_config_ini(config_ini_file_path)
    config = PyramidSetUp(settings=settings)
    return config


def get_test_magpie_app(settings=None):
    # type: (Optional[SettingsType]) -> TestApp
    """Instantiate a Magpie local test application."""
    # parse settings from ini file to pass them to the application
    config = config_setup_from_ini(get_constant("MAGPIE_INI_FILE_PATH"))
    config.include("ziggurat_foundations.ext.pyramid.sign_in")
    config.include("ziggurat_foundations.ext.pyramid.get_user")
    config.registry.settings["magpie.url"] = "http://localhost:80"
    if settings:
        config.registry.settings.update(settings)
    # create the test application
    magpie_app = TestApp(app.main({}, **config.registry.settings))
    return magpie_app


def get_app_or_url(test_item):
    # type: (AnyMagpieTestItemType) -> TestAppOrUrlType
    """Obtains the referenced Magpie local application or remote URL from `Test Case` implementation."""
    if isinstance(test_item, (TestApp, six.string_types)):
        return test_item
    app_or_url = getattr(test_item, "app", None) or getattr(test_item, "url", None)
    if not app_or_url:
        raise ValueError("Invalid test class, application or URL could not be found.")
    return app_or_url


def get_hostname(test_item):
    # type: (AnyMagpieTestItemType) -> Str
    """Obtains stored hostname in the class implementation."""
    app_or_url = get_app_or_url(test_item)
    if isinstance(app_or_url, TestApp):
        app_or_url = get_magpie_url(app_or_url.app.registry)
    return urlparse(app_or_url).hostname


def get_headers(app_or_url, header_dict):
    # type: (TestAppOrUrlType, AnyHeadersType) -> HeadersType
    """Obtains stored headers in the class implementation."""
    if isinstance(app_or_url, TestApp):
        return header_dict.items()
    return header_dict


def get_response_content_types_list(response):
    # type: (AnyResponseType) -> List[Str]
    """Obtains the specified response Content-Type header(s) without additional formatting parameters."""
    content_types = []
    known_types = ["application", "audio", "font", "example", "image", "message", "model", "multipart", "text", "video"]
    for part in response.headers["Content-Type"].split(";"):
        for sub_type in part.strip().split(","):
            if "=" not in sub_type and sub_type.split("/")[0] in known_types:
                content_types.append(sub_type)
    return content_types


def get_json_body(response):
    # type: (AnyResponseType) -> JSON
    """Obtains the JSON payload of the response regardless of its class implementation."""
    if isinstance(response, TestResponse):
        return response.json
    return response.json()


def get_service_types_for_version(version):
    available_service_types = set(services.SERVICE_TYPE_DICT.keys())
    if LooseVersion(version) <= LooseVersion("0.6.1"):
        available_service_types = available_service_types - {ServiceAccess.service_type}
    return list(available_service_types)


def warn_version(test, functionality, version, skip=True, older=False):
    # type: (AnyMagpieTestCaseType, Str, Str, bool, bool) -> None
    """
    Verifies that ``test.version`` value *minimally* has :paramref:`version` requirement to execute a test.
    (ie: ``test.version >= version``).

    If :paramref:`older` is ``True``, instead verifies that the instance is older then :paramref:`version`.
    (ie: ``test.version < version``).

    If version condition is not met, a warning is emitted and the test is skipped according to ``skip`` value.
    """
    min_req = LooseVersion(test.version) < LooseVersion(version)
    if min_req or (not min_req and older):
        if min_req:
            msg = "Functionality [{}] not yet implemented in version [{}], upgrade [>={}] required to test." \
                  .format(functionality, test.version, version)
        else:
            msg = "Functionality [{}] was deprecated in version [{}], downgrade [<{}] required to test." \
                  .format(functionality, test.version, version)
        warnings.warn(msg, FutureWarning)
        if skip:
            test.skipTest(reason=msg)   # noqa: F401


def test_request(test_item,             # type: AnyMagpieTestItemType
                 method,                # type: Str
                 path,                  # type: Str
                 data=None,             # type: Optional[Union[JSON, Str]]
                 json=None,             # type: Optional[Union[JSON, Str]]
                 body=None,             # type: Optional[Union[JSON, Str]]
                 params=None,           # type: Optional[Dict[Str, Str]]
                 timeout=5,             # type: int
                 allow_redirects=True,  # type: bool
                 content_type=None,     # type: Optional[Str]
                 headers=None,          # type: Optional[HeadersType]
                 cookies=None,          # type: Optional[CookiesType]
                 **kwargs,              # type: Any
                 ):                     # type: (...) -> AnyResponseType
    """
    Calls the request using either a :class:`webtest.TestApp` instance or :class:`requests.Request` from a string URL.

    Keyword arguments :paramref:`json`, :paramref:`data` and :paramref:`body` are all looked for to obtain the data.

    Header ``Content-Type`` is set with respect to explicit :paramref:`json` or via provided :paramref:`headers` when
    available. Explicit :paramref:`content_type` can also be provided to override all of these.

    Request cookies are set according to :paramref:`cookies`, or can be interpreted from ``Set-Cookie`` header.

    .. warning::
        When using :class:`TestApp`, some internal cookies can be stored from previous requests to retain the active
        user. Make sure to provide new set of cookies (or logout user explicitly) if different session must be used,
        otherwise they will be picked up automatically. For 'empty' cookies, provide an empty dictionary.

    :param test_item: one of `Base_Magpie_TestCase`, `webtest.TestApp` or remote server URL to call with `requests`
    :param method: request method (GET, POST, PATCH, PUT, DELETE)
    :param path: test path starting at base path that will be appended to the application's endpoint.
    :param params: query parameters added to the request path.
    :param json: explicit JSON body content to use as request body.
    :param data: body content string to use as request body, can be JSON if matching ``Content-Type`` is identified.
    :param body: alias to :paramref:`data`.
    :param content_type:
        Enforce specific content-type of provided data body. Otherwise, attempt to retrieve it from request headers.
        Inferred JSON content-type when :paramref:`json` is employed, unless overridden explicitly.
    :param headers: Set of headers to send the request. Header ``Content-Type`` is looked for if not overridden.
    :param cookies: Cookies to provide to the request.
    :param timeout: passed down to :mod:`requests` when using URL, otherwise ignored (unsupported).
    :param allow_redirects:
        Passed down to :mod:`requests` when using URL, handled manually for same behaviour when using :class:`TestApp`.
    :param kwargs: any additional keywords that will be forwarded to the request call.
    :return: response of the request
    """
    method = method.upper()
    status = kwargs.pop("status", None)

    # obtain json body from any json/data/body kw and empty {} if not specified
    # reapply with the expected webtest/requests method kw afterward
    _body = json or data or body or {}

    app_or_url = get_app_or_url(test_item)
    if isinstance(app_or_url, TestApp):
        # set 'cookies' handled by the 'TestApp' instance if not present or different
        if cookies is not None:
            cookies = dict(cookies)  # convert tuple-list as needed
            if not app_or_url.cookies or app_or_url.cookies != cookies:
                app_or_url.cookies.update(cookies)

        # obtain Content-Type header if specified to ensure it is properly applied
        kwargs["content_type"] = content_type if content_type else get_header("Content-Type", headers)

        # update path with query parameters since TestApp does not have an explicit argument when not using GET
        if params:
            path += "?" + "&".join("{!s}={!s}".format(k, v) for k, v in params.items() if v is not None)

        kwargs.update({
            "params": _body,  # TestApp uses 'params' for the body during POST (these are not the query parameters)
            "headers": dict(headers or {}),  # adjust if none provided or specified as tuple list
        })
        # convert JSON body as required
        if _body is not None and (json is not None or kwargs["content_type"] == CONTENT_TYPE_JSON):
            kwargs["params"] = json_pkg.dumps(_body, cls=json_pkg.JSONEncoder)
            kwargs["content_type"] = CONTENT_TYPE_JSON  # enforce if only 'json' keyword provided
            kwargs["headers"]["Content-Length"] = str(len(kwargs["params"]))  # need to fix with override JSON payload
        if status and status >= 300:
            kwargs["expect_errors"] = True
        resp = app_or_url._gen_request(method, path, **kwargs)  # pylint: disable=W0212  # noqa: W0212
        # automatically follow the redirect if any and evaluate its response
        max_redirect = kwargs.get("max_redirects", 5)
        while 300 <= resp.status_code < 400 and max_redirect > 0:
            resp = resp.follow()
            max_redirect -= 1
        assert max_redirect >= 0, "Maximum follow redirects reached."
        # test status accordingly if specified
        assert resp.status_code == status or status is None, "Response not matching the expected status code."
        return resp

    kwargs.pop("expect_errors", None)  # remove keyword specific to TestApp
    if json:
        kwargs["json"] = _body
    elif data or body:
        kwargs["data"] = _body
    url = "{url}{path}".format(url=app_or_url, path=path)
    return requests.request(method, url, params=params, headers=headers, cookies=cookies,
                            timeout=timeout, allow_redirects=allow_redirects, **kwargs)


def get_session_user(app_or_url, headers=None):
    # type: (TestAppOrUrlType, Optional[HeadersType]) -> AnyResponseType
    if not headers:
        headers = get_headers(app_or_url, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
    if isinstance(app_or_url, TestApp):
        resp = app_or_url.get("/session", headers=headers)
    else:
        resp = requests.get("{}/session".format(app_or_url), headers=headers)
    if resp.status_code != 200:
        raise Exception("cannot retrieve logged in user information")
    return resp


def check_or_try_login_user(test_item,                      # type: AnyMagpieTestItemType
                            username=None,                  # type: Optional[Str]
                            password=None,                  # type: Optional[Str]
                            provider=None,                  # type: Optional[Str]
                            headers=None,                   # type: Optional[Dict[Str, Str]]
                            use_ui_form_submit=False,       # type: bool
                            version=__meta__.__version__,   # type: Str
                            expect_errors=False,            # type: bool
                            ):                              # type: (...) -> OptionalHeaderCookiesType
    """
    Verifies that the required user is already logged in (or none is if ``username=None``), or attempts to log him in
    otherwise. Validates that the logged user (if any), matched the one specified by :paramref:`username`.

    :param test_item: instance of the test application or remote server URL to call
    :param username: name of the user to login or None otherwise
    :param password: password to use for login if the user was not already logged in
    :param provider: provider string to use for login (default: ``MAGPIE_DEFAULT_PROVIDER``, ie: magpie's local signin)
    :param headers: headers to include in the test request
    :param use_ui_form_submit: use Magpie UI login 'form' to obtain cookies
        (required for local :class:`WebTest.TestApp` login, ignored by requests using URL)
    :param version: server or local app version to evaluate responses with backward compatibility
    :param expect_errors: indicate if the login is expected to fail, used only if using UI form & `webtest.TestApp`
    :return: headers and cookies of the user session or (None, None)
    :raise AssertionError: if login failed or logged user session does not meet specifications (username/password)
    """
    app_or_url = get_app_or_url(test_item)
    headers = headers or {}
    resp = get_session_user(app_or_url, headers)
    body = get_json_body(resp)

    resp_cookies = None
    auth = body.get("authenticated", False)
    if auth is False and username is None:
        return None, None
    if auth is False and username is not None:
        provider = provider or get_constant("MAGPIE_DEFAULT_PROVIDER")
        data = {"user_name": username, "password": password, "provider_name": provider}

        if isinstance(app_or_url, TestApp):
            if use_ui_form_submit:
                base_url = app_or_url.app.registry.settings.get("magpie.url")
                resp = app_or_url.get(url="{}/ui/login".format(base_url))
                form = resp.forms["login_internal"]
                form["user_name"] = username
                form["password"] = password
                form["provider_name"] = provider
                resp = form.submit("submit", expect_errors=expect_errors)
                resp_cookies = app_or_url.cookies   # automatically set by form submit
            else:
                resp = app_or_url.post_json("/signin", data, headers=headers)
                resp_cookies = app_or_url.cookies  # automatically set by TestApp processing
        else:
            resp = requests.post("{}/signin".format(app_or_url), json=data, headers=headers)
            resp_cookies = resp.cookies

        # response OK (200) if directly from API /signin
        # response Found (302) if redirected UI /login
        if resp.status_code < 400:
            return resp.headers, resp_cookies

    if auth is True:
        body = TestSetup.get_UserInfo(app_or_url, override_body=body, override_version=version)
        logged_user = body.get("user_name", "")
        if username != logged_user:
            raise AssertionError("invalid user")
        if isinstance(app_or_url, TestApp):
            resp_cookies = app_or_url.cookies
        else:
            resp_cookies = resp.cookies

    return resp.headers, resp_cookies


def check_or_try_logout_user(test_item, msg=None):
    # type: (AnyMagpieTestItemType, Optional[Str]) -> None
    """
    Verifies that any user is logged out, or tries to logout him otherwise.

    :raise: Exception on any logout failure or incapability to validate logout
    """

    app_or_url = get_app_or_url(test_item)

    def _is_logged_out():
        resp = get_session_user(app_or_url)
        body = get_json_body(resp)
        auth = body.get("authenticated", False)
        return not auth

    if _is_logged_out():
        return
    resp_logout = test_request(app_or_url, "GET", "/ui/logout", allow_redirects=True)
    if isinstance(app_or_url, TestApp):
        app_or_url.reset()  # clear app cookies
    msg = ": {}".format(msg) if msg else ""
    if resp_logout.status_code >= 400:
        raise Exception("cannot validate logout" + msg)
    if _is_logged_out():
        return
    raise Exception("logout did not succeed" + msg)


def format_test_val_ref(val, ref, pre="Fail", msg=None):
    if is_null(msg):
        _msg = "({0}) Failed condition between test and reference values.".format(pre)
    else:
        _msg = "({0}) Test value: '{1}', Reference value: '{2}'".format(pre, val, ref)
        if isinstance(msg, six.string_types):
            _msg = "{}\n{}".format(msg, _msg)
    return _msg


def all_equal(iter_val, iter_ref, any_order=False):
    if not (hasattr(iter_val, "__iter__") and hasattr(iter_ref, "__iter__")):
        return False
    if len(iter_val) != len(iter_ref):
        return False
    if any_order:
        return all([it in iter_ref for it in iter_val])
    return all(it == ir for it, ir in zip(iter_val, iter_ref))


def check_all_equal(iter_val, iter_ref, msg=None, any_order=False):
    # type: (Iterable[Any], Union[Iterable[Any], NullType], Optional[Str], bool) -> None
    """
    :param iter_val: tested values.
    :param iter_ref: reference values.
    :param msg: override message to display if failing test.
    :param any_order: allow equal values to be provided in any order, otherwise order must match as well as values.
    :raises AssertionError:
        If all values in :paramref:`iter_val` are not equal to values within :paramref:`iter_ref`.
        If :paramref:`any_order` is ``False``, also raises if equal items are not in the same order.
    """
    r_it_val = repr(iter_val)
    r_it_ref = repr(iter_ref)
    assert all_equal(iter_val, iter_ref, any_order), format_test_val_ref(r_it_val, r_it_ref, pre="Equal Fail", msg=msg)


def check_val_equal(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is not equal to :paramref:`ref`."""
    assert is_null(ref) or val == ref, format_test_val_ref(val, ref, pre="Equal Fail", msg=msg)


def check_val_not_equal(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is equal to :paramref:`ref`."""
    assert is_null(ref) or val != ref, format_test_val_ref(val, ref, pre="Equal Fail", msg=msg)


def check_val_is_in(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is not in to :paramref:`ref`."""
    assert is_null(ref) or val in ref, format_test_val_ref(val, ref, pre="Is In Fail", msg=msg)


def check_val_not_in(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is in to :paramref:`ref`."""
    assert is_null(ref) or val not in ref, format_test_val_ref(val, ref, pre="Not In Fail", msg=msg)


def check_val_type(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is not an instanced of :paramref:`ref`."""
    assert isinstance(val, ref), format_test_val_ref(val, repr(ref), pre="Type Fail", msg=msg)


def check_raises(func, exception_type, msg=None):
    # type: (Callable[[], None], Type[Exception], Optional[Str]) -> Exception
    """
    Calls the callable and verifies that the specific exception was raised.

    :raise AssertionError: on failing exception check or missing raised exception.
    :returns: raised exception of expected type if it was raised.
    """
    msg = ": {}".format(msg) if msg else "."
    try:
        func()
    except Exception as exc:  # pylint: disable=W0703
        msg = "Wrong exception [{!s}] raised instead of [{!s}]{}" \
              .format(type(exc).__name__, exception_type.__name__, msg)
        assert isinstance(exc, exception_type), msg
        return exc
    raise AssertionError("Exception [{!s}] was not raised{}".format(exception_type.__name__, msg))


def check_no_raise(func, msg=None):
    # type: (Callable[[], None], Optional[Str]) -> None
    """
    Calls the callable and verifies that no exception was raised.

    :raise AssertionError: on any raised exception.
    """
    try:
        func()
    except Exception as exc:  # pylint: disable=W0703
        msg = ": {}".format(msg) if msg else "."
        raise AssertionError("Exception [{!r}] was raised when none is expected{}".format(type(exc).__name__, msg))


def check_response_basic_info(response,                         # type: AnyResponseType
                              expected_code=200,                # type: int
                              expected_type=CONTENT_TYPE_JSON,  # type: Str
                              expected_method="GET",            # type: Str
                              version=None,                     # type: Optional[Str]
                              ):                                # type: (...) -> Union[JSON, Str]
    """
    Validates basic `Magpie` API response metadata. For UI pages, employ :func:`check_ui_response_basic_info` instead.

    If the expected content-type is JSON, further validations are accomplished with specific metadata fields that are
    always expected in the response body. Otherwise, minimal validation of basic fields that can be validated regardless
    of content-type is done.

    :param response: response to validate.
    :param expected_code: status code to validate from the response.
    :param expected_type: Content-Type to validate from the response.
    :param expected_method: method 'GET', 'POST', etc. to validate from the response if an error.
    :param version: perform conditional checks according to test instance version.
    :return: json body of the response for convenience.
    """
    check_val_is_in("Content-Type", dict(response.headers), msg="Response doesn't define 'Content-Type' header.")
    content_types = get_response_content_types_list(response)
    check_val_is_in(expected_type, content_types, msg="Response doesn't match expected HTTP Content-Type header.")
    code_message = "Response doesn't match expected HTTP status code."
    if expected_type == CONTENT_TYPE_JSON:
        # provide more details about mismatching code since to help debug cause of error
        code_message += "\nReason:\n{}".format(json_pkg.dumps(get_json_body(response), indent=4), ensure_ascii=False)
    check_val_equal(response.status_code, expected_code, msg=code_message)

    if expected_type == CONTENT_TYPE_JSON:
        body = get_json_body(response)
        check_val_is_in("code", body, msg="Parameter 'code' should be in response JSON body.")
        check_val_is_in("type", body, msg="Parameter 'type' should be in response JSON body.")
        check_val_is_in("detail", body, msg="Parameter 'detail' should be in response JSON body.")
        check_val_equal(body["code"], expected_code, msg="Parameter 'code' should match the HTTP status code.")
        check_val_equal(body["type"], expected_type, msg="Parameter 'type' should match the HTTP Content-Type header.")
        check_val_not_equal(body["detail"], "", msg="Parameter 'detail' should not be empty.")
    else:
        body = response.text

    if response.status_code >= 400:
        if version and LooseVersion(version) < "2" and response.status_code not in [401, 404, 500]:
            return body  # older API error response did not all have the full request details

        # error details available for any content-type, just in different format
        check_val_is_in("url" if LooseVersion(version) >= "2" else "request_url", body)
        check_val_is_in("path" if LooseVersion(version) >= "2" else "route_name", body)
        check_val_is_in("method", body)
        if expected_type == CONTENT_TYPE_JSON:
            check_val_equal(body["method"], expected_method)

    return body


def check_ui_response_basic_info(response, expected_code=200, expected_type=CONTENT_TYPE_HTML,
                                 expected_title="Magpie Administration"):
    # type: (AnyResponseType, int, Str, Str) -> None
    """
    Validates minimal expected elements in a `Magpie` UI page.

    Number of validations is limited compared to API checks accomplished by :func:`check_response_basic_info`.
    That function should therefore be employed for responses coming directly from the API routes.

    :raises AssertionError: if any of the expected validation elements does not meet requirement.
    :returns: nothing if every check was successful.
    """
    msg = None \
        if get_header("Content-Type", response.headers) != CONTENT_TYPE_JSON \
        else "Response body: {}".format(get_json_body(response))
    check_val_equal(response.status_code, expected_code, msg=msg)
    check_val_is_in("Content-Type", dict(response.headers))
    check_val_is_in(expected_type, get_response_content_types_list(response))
    check_val_is_in(expected_title, response.text, msg=null)   # don't output big html if failing


class NullType(six.with_metaclass(SingletonMeta)):
    """
    Represents a null value to differentiate from None.
    """

    def __repr__(self):
        return "<null>"

    @staticmethod
    def __nonzero__():
        return False

    __bool__ = __nonzero__
    __len__ = __nonzero__


null = NullType()  # pylint: disable=C0103,invalid-name


def is_null(item):
    return isinstance(item, NullType) or item is null


def check_error_param_structure(json_body, param_value=null, param_name=null, param_compare=null,
                                is_param_value_literal_unicode=False, param_compare_exists=False, version=None):
    """
    Validates error response 'param' information based on different Magpie version formats.

    :param json_body: json body of the response to validate.
    :param param_value: expected 'value' of param, not verified if <Null>
    :param param_name: expected 'name' of param, not verified if <Null> or non existing for Magpie version
    :param param_compare: expected 'compare'/'param_compare' value, not verified if <Null>
    :param is_param_value_literal_unicode: param value is represented as `u'{paramValue}'` for older Magpie version
    :param param_compare_exists: verify that 'compare'/'param_compare' is in the body, not validating its actual value
    :param version: version of application/remote server to use for format validation, use local Magpie version if None
    :raises AssertionError: failing condition
    """
    check_val_type(json_body, dict)
    check_val_is_in("param", json_body)
    version = version or __meta__.__version__
    if LooseVersion(version) >= LooseVersion("0.6.3"):
        check_val_type(json_body["param"], dict)
        check_val_is_in("value", json_body["param"])
        check_val_is_in("name", json_body["param"])
        check_val_equal(json_body["param"]["name"], param_name)
        check_val_equal(json_body["param"]["value"], param_value)
        if param_compare_exists:
            check_val_is_in("compare", json_body["param"])
            check_val_equal(json_body["param"]["compare"], param_compare)
    else:
        # unicode representation was explicitly returned in value only when of string type
        if is_param_value_literal_unicode and isinstance(param_value, six.string_types):
            param_value = u"u\'{}\'".format(param_value)
        check_val_equal(json_body["param"], param_value)
        if param_compare_exists:
            check_val_is_in("param_compare", json_body)
            check_val_equal(json_body["param_compare"], param_compare)


def check_post_resource_structure(json_body, resource_name, resource_type, resource_display_name, version=None):
    """
    Validates POST /resource response information based on different Magpie version formats.

    :param json_body: json body of the response to validate.
    :param resource_name: name of the resource to validate.
    :param resource_type: type of the resource to validate.
    :param resource_display_name: display name of the resource to validate.
    :param version: version of application/remote server to use for format validation, use local Magpie version if None.
    :raises AssertionError: failing condition
    """
    version = version or __meta__.__version__
    if LooseVersion(version) >= LooseVersion("0.6.3"):
        check_val_is_in("resource", json_body)
        check_val_type(json_body["resource"], dict)
        check_val_is_in("resource_name", json_body["resource"])
        check_val_is_in("resource_display_name", json_body["resource"])
        check_val_is_in("resource_type", json_body["resource"])
        check_val_is_in("resource_id", json_body["resource"])
        check_val_equal(json_body["resource"]["resource_name"], resource_name)
        check_val_equal(json_body["resource"]["resource_display_name"], resource_display_name)
        check_val_equal(json_body["resource"]["resource_type"], resource_type)
        check_val_type(json_body["resource"]["resource_id"], int)
    else:
        check_val_is_in("resource_name", json_body)
        check_val_is_in("resource_type", json_body)
        check_val_is_in("resource_id", json_body)
        check_val_equal(json_body["resource_name"], resource_name)
        check_val_equal(json_body["resource_type"], resource_type)
        check_val_type(json_body["resource_id"], int)


def check_resource_children(resource_dict, parent_resource_id, root_service_id):
    """
    Crawls through a resource-children tree to validate data field, types and corresponding values.

    :param resource_dict: top-level 'resources' dictionary possibly containing children resources.
    :param parent_resource_id: top-level resource/service id (int)
    :param root_service_id: top-level service id (int)
    :raises AssertionError: any invalid match on expected data field, type or value
    """
    check_val_type(resource_dict, dict)
    for resource_id in resource_dict:
        check_val_type(resource_id, six.string_types)
        resource_int_id = int(resource_id)  # should by an 'int' string, no error raised
        resource_info = resource_dict[resource_id]
        check_val_is_in("root_service_id", resource_info)
        check_val_type(resource_info["root_service_id"], int)
        check_val_equal(resource_info["root_service_id"], root_service_id)
        check_val_is_in("resource_id", resource_info)
        check_val_type(resource_info["resource_id"], int)
        check_val_equal(resource_info["resource_id"], resource_int_id)
        check_val_is_in("parent_id", resource_info)
        check_val_type(resource_info["parent_id"], int)
        check_val_equal(resource_info["parent_id"], parent_resource_id)
        check_val_is_in("resource_name", resource_info)
        check_val_type(resource_info["resource_name"], six.string_types)
        check_val_is_in("resource_display_name", resource_info)
        check_val_type(resource_info["resource_display_name"], six.string_types)
        check_val_is_in("permission_names", resource_info)
        check_val_type(resource_info["permission_names"], list)
        check_val_is_in("children", resource_info)
        check_resource_children(resource_info["children"], resource_int_id, root_service_id)


class TestSetup(object):
    """Generic setup and validation methods across unittests.

    This class offers a large list of commonly reusable operations to setup or cleanup test cases.

    All methods take as input an instance of a `Test Case` derived from :class:`Base_Magpie_TestCase` (or directly a
    :class:`TestApp`, see below warning). Using this `Test Case`, common arguments such as JSON headers and user
    session cookies are automatically extracted and passed down to the relevant requests.

    The multiple parameters prefixed by ``test_`` are also automatically extracted from the referenced `Test Case`.
    For example, ``test_user_name`` will be retrieved from the `Test Case` class when this information is required for
    the corresponding test operation. All these ``test_`` parameters are used to form a *default* request payload. It
    is possible to override every individual parameter with corresponding arguments prefixed by ``override_`` keyword.
    For example, if ``override_user_name`` is provided, it will be used instead of ``test_user_name`` from the
    `Test Case` class.

    Furthermore, ``override_data`` can be provided where applicable to specify the *complete* JSON payload fields to use
    to accomplish required request. Note that doing so will ignore any auto-retrieval of ``test_`` parameters, so you
    must ensure to provide them as necessary per use-case.

    .. note::
        Since these methods are intended to *setup* test data, cookies and headers for admin-level API requests are
        employed by default. Refer to :attr:`Base_Magpie_TestCase.cookies` and :attr:`Base_Magpie_TestCase.json_headers`
        (N.B.: headers with extended JSON content-type for simplified API response body parsing). Checks that point at
        UI pages could do otherwise (e.g.: method :meth:`check_UpStatus`).

    .. warning::
        The utility methods can also be used directly with a :class:`TestApp` **IF** all required ``test_`` attributes
        for the given method are overridden with their respective arguments, since ``test_`` members will be missing.
        If a `Test Case` object is available, it should be used instead to let methods find every parameter.
    """
    # pylint: disable=C0103,invalid-name

    @staticmethod
    def get_Version(test_case, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[HeadersType], Optional[CookiesType]) -> Str
        """
        Obtains the `Magpie` version of the test instance (local or remote). This version can then be used in
        combination with :class:`LooseVersion` comparisons or :func:`warn_version` to toggle test execution of certain
        test cases that have version-dependant format, conditions or feature changes.

        This is useful *mostly* for remote server tests which could be out-of-sync compared to the current source code.
        It provides some form of backward compatibility with older instances provided that tests are updated accordingly
        when new features or changes are applied, which adds modifications to previously existing test methodologies or
        results.

        .. seealso::
            - :func:`warn_version`

        :raises AssertionError: if the response cannot successfully retrieve the test instance version.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, "GET", "/version",
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        json_body = check_response_basic_info(resp, 200)
        return json_body["version"]

    @staticmethod
    def check_UpStatus(test_case,               # type: TestAppOrUrlType
                       method,                  # type: Str
                       path,                    # type: Str
                       override_headers=null,   # type: Optional[HeadersType]
                       override_cookies=null,   # type: Optional[CookiesType]
                       expected_code=null,      # type: Optional[int]
                       expected_type=null,      # type: Optional[Str]
                       expected_title=null,     # type: Optional[Str]
                       **request_kwargs         # type: Any
                       ):                       # type: (...) -> AnyResponseType
        """
        Verifies that the Magpie UI page at very least returned an HTTP Ok response with the displayed title.
        Validates that at the bare minimum, no underlying internal error occurred from the API or UI calls.

        .. warning::
            Because this check is accomplished via the UI interface, :attr:`Base_Magpie_TestCase.test_cookies` and
            :attr:`Base_Magpie_TestCase.headers` attributes are used instead of admin-level ones as in other methods
            of :class:`TestSetup`.

        :returns: response from the rendered page for further tests.
        """
        if override_cookies is null:
            cookies = getattr(test_case, "test_cookies", getattr(test_case, "cookies", None))
        else:
            cookies = override_cookies
        if override_headers is null:
            headers = getattr(test_case, "test_headers", getattr(test_case, "headers", None))
        else:
            headers = override_headers
        resp = test_request(test_case, method, path, headers=headers, cookies=cookies, **request_kwargs)
        kwargs = {}
        if expected_title is null:
            kwargs["expected_title"] = getattr(test_case, "magpie_title", "Magpie Administration")
        else:
            kwargs["expected_title"] = expected_title
        if expected_code is not null:
            kwargs["expected_code"] = expected_code
        if expected_type is not null:
            kwargs["expected_type"] = expected_type
        check_ui_response_basic_info(resp, **kwargs)
        return resp

    @staticmethod
    def check_FormSubmit(test_case,                         # type: AnyMagpieTestCaseType
                         form_match,                        # type: Union[Str, int, Dict[Str, Str]]
                         form_data=None,                    # type: Optional[Dict[Str, AnyValue]]
                         form_submit="submit",              # type: Union[Str, int]
                         previous_response=None,            # type: AnyResponseType
                         path=None,                         # type: Optional[Str]
                         method="GET",                      # type: Str
                         timeout=20,                        # type: int
                         max_redirect=5,                    # type: int
                         expected_code=200,                 # type: int
                         expected_type=CONTENT_TYPE_HTML,   # type: Str
                         expect_errors=False,               # type: bool
                         override_cookies=null,             # type: Optional[CookiesType]
                         ):                                 # type: (...) -> AnyResponseType
        """
        Simulates the submission of a UI form to evaluate the status of the resulting page. Follows any redirect if the
        submission results into a HTTP Move (3xx) response to be redirected towards another page request.

        Successive calls using form submits can be employed to simulate sequential page navigation by providing back
        the returned `response` object as input to the following page with argument :paramref:`previous_response`.

        .. code-block:: json

            svc_resp = check_FormSubmit(test, form_match="goto_add_service", path="/ui/services")
            add_resp = check_FormSubmit(test, form_match="add_service", form_data={...}, previous_response=svc_resp)

        :param test_case: `Test Case` to retrieve the instance and parameters to send requests to.
        :param form_match:
            Can be a form name, the form index (from all available forms on page) or an
            iterable of key/values of form fields to search for a match (first match is used if many are available).
        :param form_data: specifies matched form fields to be filed as if entered from UI input using given key/value.
        :param form_submit: specifies which `button` by name or index to submit within the matched form.
        :param path:
            Required page location where to send a request to fetch the required form, *unless* provided through
            :paramref:`previous_response` which must contain the form being looked for in its body.
        :param method: combined with :paramref:`path` when request is need to fetch the form.
        :param previous_response: pre-executed request where the form can be directly looked for in its body.
        :param timeout: response timeout to be used with :paramref:`path` when request must be sent.
        :param max_redirect: limits how many times follow-redirect from HTTP 3xx responses can be accomplished.
        :param expected_code: validate the HTTP status code from the response (returned or provided one).
        :param expected_type: validate the content-type of the response (returned or provided one).
        :param expect_errors: indicate if error HTTP status codes (>=400) are considered normal in the response.
        :param override_cookies: enforce some cookies in the request.

        :returns: response from the rendered page for further tests
        :raises AssertionError: if any check along the ways results into error or unexpected state.
        """
        app_or_url = get_app_or_url(test_case)
        if not isinstance(app_or_url, TestApp):
            test_case.skipTest(reason="test form submit with remote URL not implemented")
        if isinstance(previous_response, TestResponse):
            resp = previous_response
        else:
            resp = test_request(app_or_url, method, path, timeout=timeout,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
        check_val_equal(resp.status_code, 200, msg="Cannot test form submission, initial page returned an error.")
        form = None
        if isinstance(form_match, (int, six.string_types)):
            form = resp.forms[form_match]
        else:
            # select form if all key/value pairs specified match the current one
            for f in resp.forms.values():
                f_fields = [(fk, fv[0].value) for fk, fv in f.fields.items()]
                if all((mk, mv) in f_fields for mk, mv in form_match.items()):
                    form = f
                    break
        if not form:
            test_case.fail("could not find requested form for submission "
                           "[form_match: {!r}, form_submit: {!r}, form_data: {!r}]"
                           .format(form_match, form_submit, form_data))
        if form_data:
            for f_field, f_value in dict(form_data).items():
                form[f_field] = f_value
        resp = form.submit(form_submit, expect_errors=expect_errors)
        while 300 <= resp.status_code < 400 and max_redirect > 0:
            resp = resp.follow()
        check_ui_response_basic_info(resp, expected_code=expected_code, expected_type=expected_type)
        return resp

    @staticmethod
    def check_Unauthorized(test_case, method, path, expected_type=CONTENT_TYPE_JSON, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Str, Str, Str, Optional[CookiesType]) -> Union[JSON, Str]
        """
        Verifies that Magpie returned an Unauthorized response.
        Validates that at the bare minimum, no underlying internal error occurred from the API or UI calls.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, method, path,
                            headers={"Accept": expected_type},
                            cookies=override_cookies if override_cookies is not null else test_case.cookies,
                            expect_errors=True)
        if is_magpie_ui_path(path):
            check_ui_response_basic_info(resp, expected_code=401, expected_type=expected_type)
            if expected_type == CONTENT_TYPE_JSON:
                return get_json_body(resp)
            return resp.text
        return check_response_basic_info(resp, expected_code=401, expected_type=expected_type, expected_method=method)

    @staticmethod
    def get_AnyServiceOfTestServiceType(test_case,                      # type: AnyMagpieTestCaseType
                                        override_service_type=null,     # type: Optional[Str]
                                        override_headers=null,          # type: Optional[HeadersType]
                                        override_cookies=null,          # type: Optional[CookiesType]
                                        ):                              # type: (...) -> JSON
        """Obtains the first service from all available services that match the test service type.

        :raises AssertionError: if the response could not retrieve the test service-type or any service of such type.
        """
        app_or_url = get_app_or_url(test_case)
        svc_type = override_service_type if override_service_type is not null else test_case.test_service_type
        path = "/services/types/{}".format(svc_type)
        resp = test_request(app_or_url, "GET", path,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")
        check_val_is_in("services", json_body)
        check_val_is_in(svc_type, json_body["services"])
        check_val_not_equal(len(json_body["services"][svc_type]), 0,
                            msg="Missing any required service of type: '{}'".format(test_case.test_service_type))
        services_dict = json_body["services"][svc_type]
        return list(services_dict.values())[0]

    @staticmethod
    def create_TestServiceResource(test_case,                       # type: AnyMagpieTestCaseType
                                   override_service_name=null,      # type: Optional[Str]
                                   override_resource_name=null,     # type: Optional[Str]
                                   override_resource_type=null,     # type: Optional[Str]
                                   override_data=null,              # type: Optional[JSON]
                                   override_headers=null,           # type: Optional[HeadersType]
                                   override_cookies=null,           # type: Optional[CookiesType]
                                   ):                               # type: (...) -> JSON
        """Creates the test resource nested *immediately* under the test service. Test service *must* exist beforehand.

        :raises AssertionError: if the response correspond to failure to create the test resource.
        """
        app_or_url = get_app_or_url(test_case)
        TestSetup.create_TestService(test_case)
        svc_name = override_service_name if override_service_name is not null else test_case.test_service_name
        path = "/services/{svc}/resources".format(svc=svc_name)
        data = override_data if override_data is not null else {
            "resource_name": override_resource_name or test_case.test_resource_name,
            "resource_type": override_resource_type or test_case.test_resource_type,
        }
        resp = test_request(app_or_url, "POST", path, json=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def create_TestResource(test_case,                      # type: AnyMagpieTestCaseType
                            parent_resource_id,             # type: int
                            override_resource_name=null,    # type: Optional[Str]
                            override_resource_type=null,    # type: Optional[Str]
                            override_data=null,             # type: Optional[JSON]
                            override_headers=null,          # type: Optional[HeadersType]
                            override_cookies=null,          # type: Optional[CookiesType]
                            ):                              # type: (...) -> JSON
        """Creates the test resource nested *immediately* under the parent resource id.
        Parent resource *must* exist beforehand and *must* support nested children resource.
        For convenience, all details of the successfully created resource are fetched and returned.

        :raises AssertionError: if the response correspond to failure to create the test resource.
        """
        app_or_url = get_app_or_url(test_case)
        path = "/resources/{}".format(parent_resource_id)
        resp = test_request(app_or_url, "GET", path,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        check_response_basic_info(resp)
        data = override_data if override_data is not null else {
            "resource_name": override_resource_name or test_case.test_resource_name,
            "resource_type": override_resource_type or test_case.test_resource_type,
            "parent_id": parent_resource_id,
        }
        # creation response provides only 'basic' info, fetch detailed ones with additional get
        resp = test_request(app_or_url, "POST", "/resources", json=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        body = check_response_basic_info(resp, 201, expected_method="POST")
        info = TestSetup.get_ResourceInfo(test_case, override_body=body)
        path = "/resources/{}".format(info["resource_id"])
        resp = test_request(app_or_url, "GET", path,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        return check_response_basic_info(resp)

    @staticmethod
    def get_ResourceInfo(test_case,                 # type: AnyMagpieTestCaseType
                         override_body=None,        # type: Optional[JSON]
                         full_detail=False,         # type: bool
                         resource_id=None,          # type: Optional[int]
                         override_headers=null,     # type: Optional[HeadersType]
                         override_cookies=null,     # type: Optional[CookiesType]
                         ):                         # type: (...) -> JSON
        """
        Obtains in a backward compatible way the resource details based on resource response body and the tested
        instance version.

        Alternatively to :paramref:`body`, one can directly fetch details from provided :paramref:`resource_id`.
        Otherwise, if :paramref:`body` was provided and :paramref:`full_detail` is requested, executes another request
        to obtain the additional information with inferred resource ID available from the body. This obtains additional
        details resource such as applicable permissions that are not available from base request body returned at
        resource creation. This is essentially the same as requesting the details directly with :paramref:`resource_id`.
        """
        body = override_body
        if override_body:
            if LooseVersion(test_case.version) >= LooseVersion("0.6.3"):
                check_val_is_in("resource", body)
                check_val_type(body["resource"], dict)
                body = body["resource"]
            resource_id = body["resource_id"]
        if resource_id and full_detail:
            resp = test_request(test_case, "GET", "/resources/{}".format(resource_id),
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            body = check_response_basic_info(resp)
            body = TestSetup.get_ResourceInfo(test_case, override_body=body, resource_id=None, full_detail=False)
        return body

    @staticmethod
    def get_ExistingTestServiceInfo(test_case,                      # type: AnyMagpieTestCaseType
                                    override_service_name=null,     # type: Optional[Str]
                                    override_headers=null,          # type: Optional[HeadersType]
                                    override_cookies=null,          # type: Optional[CookiesType]
                                    ):                              # type: (...) -> JSON
        """Obtains test service details.

        :raises AssertionError: if the response correspond to missing service or failure to retrieve it.
        """
        app_or_url = get_app_or_url(test_case)
        svc_name = override_service_name if override_service_name is not null else test_case.test_service_name
        path = "/services/{svc}".format(svc=svc_name)
        resp = test_request(app_or_url, "GET", path,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        json_body = get_json_body(resp)
        svc_getter = "service"
        if LooseVersion(test_case.version) < LooseVersion("0.9.1"):
            svc_getter = svc_name
        return json_body[svc_getter]

    @staticmethod
    def get_TestServiceDirectResources(test_case,                       # type: AnyMagpieTestCaseType
                                       ignore_missing_service=False,    # type: bool
                                       override_service_name=null,      # type: Optional[Str]
                                       override_headers=null,           # type: Optional[HeadersType]
                                       override_cookies=null,           # type: Optional[CookiesType]
                                       ):                               # type: (...) -> List[JSON]
        """Obtains test resources nested *immediately* under test service.

        :raises AssertionError: if the response correspond to missing service or resources.
        """
        app_or_url = get_app_or_url(test_case)
        svc_name = override_service_name if override_service_name is not null else test_case.test_service_name
        path = "/services/{svc}/resources".format(svc=svc_name)
        resp = test_request(app_or_url, "GET", path,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies,
                            expect_errors=ignore_missing_service)
        if ignore_missing_service and resp.status_code == 404:
            return []
        json_body = get_json_body(resp)
        resources = json_body[svc_name]["resources"]
        return [resources[res] for res in resources]

    @staticmethod
    def check_NonExistingTestServiceResource(test_case, override_service_name=null, override_resource_name=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[Str]) -> None
        """Validates that test resource nested *immediately* under test service does not exist.
        Skips validation if the test service does not exist.

        :raises AssertionError: if the response correspond to existing resource under the service.
        """
        resources = TestSetup.get_TestServiceDirectResources(test_case,
                                                             override_service_name=override_service_name,
                                                             ignore_missing_service=True)
        resources_names = [res["resource_name"] for res in resources]
        check_val_not_in(override_resource_name or test_case.test_resource_name, resources_names)

    @staticmethod
    def delete_TestServiceResource(test_case,                       # type: AnyMagpieTestCaseType
                                   override_service_name=null,      # type: Optional[Str]
                                   override_resource_name=null,     # type: Optional[Str]
                                   override_headers=null,           # type: Optional[HeadersType]
                                   override_cookies=null,           # type: Optional[CookiesType]
                                   ):                               # type: (...) -> None
        """Deletes the test resource under test service. If it does not exist, skip. Otherwise, delete it and validate.

        :raises AssertionError: if any response does not correspond to non existing service's resource after execution.
        """
        app_or_url = get_app_or_url(test_case)
        resource_name = override_resource_name if override_resource_name is not null else test_case.test_resource_name
        resources = TestSetup.get_TestServiceDirectResources(test_case, ignore_missing_service=True)
        test_resource = list(filter(lambda r: r["resource_name"] == resource_name, resources))
        # delete as required, skip if non-existing
        if len(test_resource) > 0:
            resource_id = test_resource[0]["resource_id"]
            svc_name = override_service_name if override_service_name is not null else test_case.test_service_name
            path = "/services/{svc}/resources/{res_id}".format(svc=svc_name, res_id=resource_id)
            resp = test_request(app_or_url, "DELETE", path,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            check_val_equal(resp.status_code, 200)
        TestSetup.check_NonExistingTestServiceResource(test_case)

    @staticmethod
    def create_TestService(test_case,                   # type: AnyMagpieTestCaseType
                           override_service_name=null,  # type: Optional[Str]
                           override_service_type=null,  # type: Optional[Str]
                           override_headers=null,       # type: Optional[HeadersType]
                           override_cookies=null,       # type: Optional[CookiesType]
                           ):                           # type: (...) -> JSON
        """Creates the test service. If already exists, deletes it. Then, attempt creation.

        :raises AssertionError: if any response does not correspond to successful service creation from scratch.
        """
        app_or_url = get_app_or_url(test_case)
        svc_name = override_service_name if override_service_name is not null else test_case.test_service_name
        svc_type = override_service_type if override_service_type is not null else test_case.test_service_type
        data = {
            "service_name": svc_name,
            "service_type": svc_type,
            "service_url": "http://localhost:9000/{}".format(svc_name)
        }
        resp = test_request(app_or_url, "POST", "/services", json=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies,
                            expect_errors=True)
        if resp.status_code == 409:
            path = "/services/{svc}".format(svc=svc_name)
            resp = test_request(app_or_url, "GET", path,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            body = check_response_basic_info(resp, 200, expected_method="GET")
            if LooseVersion(test_case.version) < LooseVersion("0.9.1"):
                body.update({"service": body[svc_name]})
                body.pop(svc_name)
            return body
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def check_NonExistingTestService(test_case, override_service_name=null):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Validates that the test service does not exist.

        :raises AssertionError: if the response does not correspond to missing service.
        """
        services_info = TestSetup.get_RegisteredServicesList(test_case)
        services_names = [svc["service_name"] for svc in services_info]
        service_name = override_service_name if override_service_name is not null else test_case.test_service_name
        check_val_not_in(service_name, services_names)

    @staticmethod
    def delete_TestService(test_case, override_service_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """Deletes the test service. If non existing, skip. Otherwise, proceed to remove it.

        :raises AssertionError: if the response does not correspond to successful validation or removal of the service.
        """
        app_or_url = get_app_or_url(test_case)
        service_name = override_service_name if override_service_name is not null else test_case.test_service_name
        services_info = TestSetup.get_RegisteredServicesList(test_case)
        test_service = list(filter(lambda r: r["service_name"] == service_name, services_info))
        # delete as required, skip if non-existing
        if len(test_service) > 0:
            path = "/services/{svc_name}".format(svc_name=service_name)
            resp = test_request(app_or_url, "DELETE", path,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            check_val_equal(resp.status_code, 200)
        TestSetup.check_NonExistingTestService(test_case, override_service_name=service_name)

    @staticmethod
    def get_RegisteredServicesList(test_case, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[HeadersType], Optional[CookiesType]) -> List[Str]
        """Obtains the list of registered services names.

        :raises AssertionError: if the response does not correspond to successful retrieval of user names.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, "GET", "/services",
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")

        # prepare a flat list of registered services
        services_list = list()
        for svc_type in json_body["services"]:
            services_of_type = json_body["services"][svc_type]
            services_list.extend(services_of_type.values())
        return services_list

    @staticmethod
    def delete_TestResource(test_case, resource_id, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, int, Optional[HeadersType], Optional[CookiesType]) -> None
        """Deletes the test resource directly using its ID. If non existing, skips. Otherwise, delete and validate.

        :raises AssertionError: if the response does not correspond to non existing resource.
        """
        app_or_url = get_app_or_url(test_case)
        path = "/resources/{res_id}".format(res_id=resource_id)
        resp = test_request(app_or_url, "DELETE", path, expect_errors=True,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        check_val_is_in(resp.status_code, [200, 404])
        if resp.status_code == 200:
            resp = test_request(app_or_url, "GET", path, expect_errors=True,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            check_val_is_in(resp.status_code, 404)

    @staticmethod
    def get_RegisteredUsersList(test_case, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[HeadersType], Optional[CookiesType]) -> List[Str]
        """Obtains the list of registered users.

        :raises AssertionError: if the response does not correspond to successful retrieval of user names.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, "GET", "/users",
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")
        return json_body["user_names"]

    @staticmethod
    def check_NonExistingTestUser(test_case, override_user_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """Ensures that the test user does not exist.

        :raises AssertionError: if the test user exists.
        """
        users = TestSetup.get_RegisteredUsersList(test_case,
                                                  override_headers=override_headers, override_cookies=override_cookies)
        user_name = override_user_name if override_user_name is not null else test_case.test_user_name
        check_val_not_in(user_name, users)

    @staticmethod
    def create_TestUser(test_case,                  # type: AnyMagpieTestCaseType
                        override_data=null,         # type: Optional[JSON]
                        override_user_name=null,    # type: Optional[Str]
                        override_email=null,        # type: Optional[Str]
                        override_password=null,     # type: Optional[Str]
                        override_group_name=null,   # type: Optional[Str]
                        override_headers=null,      # type: Optional[HeadersType]
                        override_cookies=null,      # type: Optional[CookiesType]
                        ):                          # type: (...) -> JSON
        """Creates the test user.

        :raises AssertionError: if the request response does not match successful creation.
        """
        app_or_url = get_app_or_url(test_case)
        if override_data is not null:
            data = override_data
        else:
            data = {
                "user_name": override_user_name if override_user_name is not null else test_case.test_user_name,
                "password": override_password if override_password is not null else test_case.test_user_name,
                "group_name": override_group_name if override_group_name is not null else test_case.test_group_name,
            }
            data["email"] = override_email if override_email is not null else "{}@mail.com".format(data["user_name"])
        resp = test_request(app_or_url, "POST", "/users", json=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def delete_TestUser(test_case, override_user_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """Ensures that the test user does not exist. If it does, deletes him. Otherwise, skip.

        :raises AssertionError: if any request response does not match successful validation or removal from group.
        """
        app_or_url = get_app_or_url(test_case)
        users = TestSetup.get_RegisteredUsersList(test_case,
                                                  override_headers=override_headers, override_cookies=override_cookies)
        user_name = override_user_name if override_user_name is not null else test_case.test_user_name
        # delete as required, skip if non-existing
        if user_name in users:
            path = "/users/{usr}".format(usr=user_name)
            resp = test_request(app_or_url, "DELETE", path,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            check_response_basic_info(resp, 200, expected_method="DELETE")
        TestSetup.check_NonExistingTestUser(test_case, override_user_name=user_name,
                                            override_headers=override_headers, override_cookies=override_cookies)

    @staticmethod
    def get_UserInfo(test_case,                 # type: AnyMagpieTestCaseType
                     override_body=None,        # type: JSON
                     override_username=null,    # type: Optional[Str]
                     override_version=null,     # type: Optional[Str]
                     override_headers=null,     # type: Optional[HeadersType]
                     override_cookies=null,     # type: Optional[CookiesType]
                     ):                         # type: (...) -> JSON
        """
        Obtains in a backward compatible way the user details based on response body and the tested instance version.

        Executes an HTTP request with the currently logged user (using cookies/headers) or for another user (using
        :paramref:`override_username` (needs admin-level login cookies/headers).
        Using :paramref:`body`, one can directly fetch details from JSON body instead of performing the request.
        Employed version is extracted from the :paramref:`test_case` unless provided by :paramref:`override_version`.
        """
        if override_body:
            body = override_body
        else:
            username = override_username if override_username is not null else get_constant("MAGPIE_LOGGED_USER")
            resp = test_request(test_case, "GET", "/users/{}".format(username),
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            body = check_response_basic_info(resp)
        version = override_version if override_version is not null else test_case.version
        if LooseVersion(version) >= LooseVersion("0.6.3"):
            check_val_is_in("user", body)
            body = body["user"]
        return body or {}

    @staticmethod
    def check_UserGroupMembership(test_case,                    # type: AnyMagpieTestCaseType
                                  member=True,                  # type: bool
                                  override_user_name=null,      # type: Optional[Str]
                                  override_group_name=null,     # type: Optional[Str]
                                  override_headers=null,        # type: Optional[HeadersType]
                                  override_cookies=null,        # type: Optional[CookiesType]
                                  ):                            # type: (...) -> None
        """Ensures that the test user is a member or not of the test group (according to :paramref:`member` value).

        :raises AssertionError: if the request response does not validate of membership status of the user to the group.
        """
        app_or_url = get_app_or_url(test_case)
        usr_name = override_user_name if override_user_name is not null else test_case.test_user_name
        grp_name = override_group_name if override_group_name is not null else test_case.test_group_name
        cookies = override_cookies if override_cookies is not null else test_case.cookies
        headers = override_headers if override_headers is not null else test_case.json_headers
        path = "/groups/{grp}/users".format(grp=grp_name)
        resp = test_request(app_or_url, "GET", path, headers=headers, cookies=cookies)
        body = check_response_basic_info(resp, 200, expected_method="GET")
        if member:
            check_val_is_in(usr_name, body["user_names"])
        else:
            check_val_not_in(usr_name, body["user_names"])

    @staticmethod
    def assign_TestUserGroup(test_case,                 # type: AnyMagpieTestCaseType
                             override_user_name=null,   # type: Optional[Str]
                             override_group_name=null,  # type: Optional[Str]
                             override_headers=null,     # type: Optional[HeadersType]
                             override_cookies=null,     # type: Optional[CookiesType]
                             ):                         # type: (...) -> None
        """Ensures that the test user is a member of the test group. If already a member, skips. Otherwise, adds him.

        :raises AssertionError: if any request response does not match successful validation or assignation to group.
        """
        app_or_url = get_app_or_url(test_case)
        usr_name = override_user_name if override_user_name is not null else test_case.test_user_name
        grp_name = override_group_name if override_group_name is not null else test_case.test_group_name
        path = "/groups/{grp}/users".format(grp=grp_name)
        resp = test_request(app_or_url, "GET", path,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        body = check_response_basic_info(resp, 200, expected_method="GET")
        if usr_name not in body["user_names"]:
            path = "/users/{usr}/groups".format(usr=usr_name)
            data = {"group_name": grp_name}
            resp = test_request(app_or_url, "POST", path, data=data,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            check_response_basic_info(resp, 201, expected_method="POST")
        TestSetup.check_UserGroupMembership(test_case, override_user_name=usr_name, override_group_name=grp_name,
                                            override_headers=override_headers, override_cookies=override_cookies)

    @staticmethod
    def get_RegisteredGroupsList(test_case, only_discoverable=False, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, bool, Optional[HeadersType], Optional[CookiesType]) -> List[Str]
        """Obtains existing group names. Optional only return the publicly discoverable ones.

        :raises AssertionError: if the request response does not match successful groups retrieval.
        """
        app_or_url = get_app_or_url(test_case)
        path = "/register/groups" if only_discoverable else "/groups"
        resp = test_request(app_or_url, "GET", path,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")
        return json_body["group_names"]

    @staticmethod
    def check_NonExistingTestGroup(test_case, override_group_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """Validate that test group does not exist.

        :raises AssertionError: if the test group exists
        """
        groups = TestSetup.get_RegisteredGroupsList(test_case,
                                                    override_headers=override_headers,
                                                    override_cookies=override_cookies)
        group_name = override_group_name if override_group_name is not null else test_case.test_group_name
        check_val_not_in(group_name, groups)

    @staticmethod
    def create_TestGroup(test_case,                     # type: AnyMagpieTestCaseType
                         override_group_name=null,      # type: Optional[Str]
                         override_discoverable=null,    # type: Optional[bool]
                         override_data=null,            # type: Optional[JSON]
                         override_headers=null,         # type: Optional[HeadersType]
                         override_cookies=null,         # type: Optional[CookiesType]
                         ):                             # type: (...) -> JSON
        """Create the test group.

        :raises AssertionError: if the request does not have expected response matching successful creation.
        """
        app_or_url = get_app_or_url(test_case)
        data = override_data
        if override_data is null:
            data = {"group_name": override_group_name if override_group_name is not null else test_case.test_group_name}
            # only add 'discoverable' if explicitly provided here to preserve original behaviour of 'no value provided'
            if override_discoverable is not null:
                data["discoverable"] = override_discoverable
        resp = test_request(app_or_url, "POST", "/groups", json=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def delete_TestGroup(test_case, override_group_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """Delete the test group. Skip operation if the group does not exist.

        :raises AssertionError: if the request does not have expected response matching successful deletion.
        :return: nothing. Group is ensured to not exist.
        """
        app_or_url = get_app_or_url(test_case)
        groups = TestSetup.get_RegisteredGroupsList(test_case)
        group_name = override_group_name if override_group_name is not null else test_case.test_group_name
        # delete as required, skip if non-existing
        if group_name in groups:
            path = "/groups/{grp}".format(grp=group_name)
            resp = test_request(app_or_url, "DELETE", path,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            check_response_basic_info(resp, 200, expected_method="DELETE")
        TestSetup.check_NonExistingTestGroup(test_case, override_group_name=group_name,
                                             override_headers=override_headers, override_cookies=override_cookies)
