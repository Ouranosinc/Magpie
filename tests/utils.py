import functools
import itertools
import json as json_pkg  # avoid conflict name with json argument employed for some function
import unittest
import warnings
from distutils.version import LooseVersion
from typing import TYPE_CHECKING

import mock
import pytest
import requests
import requests.exceptions
import six
from pyramid.httpexceptions import HTTPException
from pyramid.settings import asbool
from pyramid.testing import DummyRequest, setUp as PyramidSetUp
from six.moves.urllib.parse import urlparse
from webtest.app import AppError, TestApp  # noqa
from webtest.forms import Form
from webtest.response import TestResponse

from magpie import __meta__, app, services
from magpie.constants import get_constant
from magpie.permissions import Access, PermissionSet, Scope
from magpie.services import SERVICE_TYPE_DICT, ServiceAccess
from magpie.utils import (
    CONTENT_TYPE_HTML,
    CONTENT_TYPE_JSON,
    SingletonMeta,
    get_header,
    get_magpie_url,
    get_settings_from_config_ini
)

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Callable, Collection, Dict, Iterable, List, Optional, Tuple, Type, Union

    from pyramid.request import Request

    import tests.interfaces as ti
    from magpie.services import ServiceInterface
    from magpie.typedefs import (
        JSON,
        AnyCookiesType,
        AnyHeadersType,
        AnyPermissionType,
        AnyResponseType,
        AnyValue,
        CookiesType,
        HeadersType,
        SettingsType,
        Str
    )

    # pylint: disable=C0103,invalid-name
    AnyMagpieTestCaseType = Union[Type[ti.BaseTestCase], ti.BaseTestCase,
                                  Type[ti.AdminTestCase], ti.AdminTestCase,
                                  Type[ti.UserTestCase], ti.UserTestCase]
    OptionalHeaderCookiesType = Tuple[Optional[AnyHeadersType], Optional[AnyCookiesType]]
    TestAppOrUrlType = Union[Str, TestApp]
    AnyMagpieTestItemType = Union[AnyMagpieTestCaseType, TestAppOrUrlType]

OPTIONAL_STRING_TYPES = six.string_types + tuple([type(None)])


class RunOption(object):
    """
    Defines a portable marker that can activate/disable tests from environment variable or :mod:`pytest` marker.

    Offers compatibility between :mod:`pytest` conditional markers and :mod:`unittest` skip decorators.
    With these options, specific tests can be executed equivalently with following methods::

        [env] MAGPIE_TEST_USERS = false
        pytest tests

        pytest tests -m "not users"

    All ``MAGPIE_TEST_<option>`` variables are *enabled* by default.

    .. seealso::
        :func:`make_run_option_decorator`
    """
    __slots__ = ["_name", "_enabled", "_marker", "_description"]
    __name__ = "RunOption"  # backward fix for Python 2 and 'functools.wraps'

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
    @functools.wraps(run_option)
    def wrap(test_func, *_, **__):
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


class TestVersion(LooseVersion):
    """
    Special version supporting ``latest`` keyword to ignore safeguard check of :func:`warn_version` during development.

    .. seealso::
        Environment variable ``MAGPIE_TEST_VERSION`` should be set with the desired version or ``latest`` to evaluate
        even new features above the last tagged version.
    """
    def __init__(self, vstring):
        if isinstance(vstring, (TestVersion, LooseVersion)):
            self.version = vstring.version
            return
        if vstring == "latest":
            self.version = vstring  # noqa
            return
        super(TestVersion, self).__init__(vstring)

    def _cmp(self, other):
        if not isinstance(other, TestVersion):
            other = TestVersion(other)
        if self.version == "latest" and other.version == "latest":
            return 0
        if self.version == "latest":
            return 1
        if other.version == "latest":
            return -1
        return super(TestVersion, self)._cmp(other)


@six.add_metaclass(SingletonMeta)
class NullType(object):
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


def config_setup_from_ini(config_ini_file_path):
    settings = get_settings_from_config_ini(config_ini_file_path)
    config = PyramidSetUp(settings=settings)
    return config


def get_test_magpie_app(settings=None):
    # type: (Optional[SettingsType]) -> TestApp
    """
    Instantiate a Magpie local test application.
    """
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
    """
    Obtains the referenced Magpie test application, local application or remote URL from `Test Case` implementation.
    """
    if isinstance(test_item, (TestApp, six.string_types)):
        return test_item
    test_app = getattr(test_item, "test_app", None)
    if test_app and isinstance(test_app, TestApp):
        return test_app
    app_or_url = getattr(test_item, "app", None) or getattr(test_item, "url", None)
    if not app_or_url:
        raise ValueError("Invalid test class, application or URL could not be found.")
    return app_or_url


def get_hostname(test_item):
    # type: (AnyMagpieTestItemType) -> Str
    """
    Obtains stored hostname in the class implementation.
    """
    app_or_url = get_app_or_url(test_item)
    if isinstance(app_or_url, TestApp):
        app_or_url = get_magpie_url(app_or_url.app.registry)
    return urlparse(app_or_url).hostname


def get_headers(app_or_url, header_dict):
    # type: (TestAppOrUrlType, AnyHeadersType) -> HeadersType
    """
    Obtains stored headers in the class implementation.
    """
    if isinstance(app_or_url, TestApp):
        return header_dict.items()
    return header_dict


def get_response_content_types_list(response):
    # type: (AnyResponseType) -> List[Str]
    """
    Obtains the specified response Content-Type header(s) without additional formatting parameters.
    """
    content_types = []
    known_types = ["application", "audio", "font", "example", "image", "message", "model", "multipart", "text", "video"]
    for part in response.headers["Content-Type"].split(";"):
        for sub_type in part.strip().split(","):
            if "=" not in sub_type and sub_type.split("/")[0] in known_types:
                content_types.append(sub_type)
    return content_types


def get_json_body(response):
    # type: (AnyResponseType) -> JSON
    """
    Obtains the JSON payload of the response regardless of its class implementation.
    """
    if isinstance(response, TestResponse):
        return response.json
    return response.json()


def get_service_types_for_version(version):
    # type: (Str) -> List[ServiceInterface]
    available_service_types = set(services.SERVICE_TYPE_DICT.keys())
    if TestVersion(version) <= TestVersion("0.6.1"):
        available_service_types = available_service_types - {ServiceAccess.service_type}
    return list(sorted(available_service_types))


def warn_version(test, functionality, version, skip=True, older=False):
    # type: (Union[AnyMagpieTestCaseType, Str], Str, Str, bool, bool) -> None
    """
    Verifies that ``test.version`` value *minimally* has :paramref:`version` requirement to execute a test.
    (ie: ``test.version >= version``).

    If :paramref:`older` is ``True``, instead verifies that the instance is older then :paramref:`version`.
    (ie: ``test.version < version``).

    If version condition is not met, a warning is emitted and the test is skipped according to ``skip`` value.

    Optionally, the reference version can be directly provided as string using :paramref:`test` instead of `Test Case`.
    """
    if isinstance(test, six.string_types):
        test_version = test
    else:
        test_version = TestSetup.get_Version(test)
    min_req = TestVersion(test_version) < TestVersion(version)
    if min_req or (not min_req and older):
        if min_req:
            msg = "Functionality [{}] not yet implemented in version [{}], upgrade [>={}] required to test." \
                  .format(functionality, test_version, version)
        else:
            msg = "Functionality [{}] was deprecated in version [{}], downgrade [<{}] required to test." \
                  .format(functionality, test_version, version)
        warnings.warn(msg, FutureWarning)
        if skip:
            test.skipTest(reason=msg)   # noqa: F401


def json_msg(json_body, msg=null):
    # type: (JSON, Optional[Str]) -> Str
    """
    Generates a message string with formatted JSON body for display with easier readability.
    """
    json_str = json_pkg.dumps(json_body, indent=4, ensure_ascii=False)
    if msg is not null:
        return "{}\n{}".format(msg, json_str)
    return json_str


def mock_get_settings(test):
    """
    Decorator to mock :func:`magpie.utils.get_settings` to allow retrieval of settings from :class:`DummyRequest`.

    .. warning::
        Only apply on test methods (not on class TestCase) to ensure that :mod:`pytest` can collect them correctly.
    """
    from magpie.utils import get_settings as real_get_settings

    def mocked(container):
        if isinstance(container, DummyRequest):
            return container.registry.settings
        return real_get_settings(container)

    @functools.wraps(test)
    def wrapped(*_, **__):
        # mock.patch("magpie.services.get_settings", side_effect=mocked)
        with mock.patch("magpie.utils.get_settings", side_effect=mocked):
            return test(*_, **__)
    return wrapped


def mock_request(request_path_query="",     # type: Str
                 method="GET",              # type: Str
                 params=None,               # type: Optional[Dict[Str, Str]]
                 body="",                   # type: Union[Str, JSON]
                 content_type=None,         # type: Optional[Str]
                 headers=None,              # type: Optional[AnyHeadersType]
                 cookies=None,              # type: Optional[AnyCookiesType]
                 settings=None,             # type: SettingsType
                 ):                         # type: (...) -> Request
    """
    Generates a fake request with provided arguments.

    Can be employed by functions that expect a request object as input to retrieve details such as body content, the
    request path, or internal settings, but that no actual request needs to be accomplished.
    """
    parts = request_path_query.split("?")
    path = parts[0]
    query = dict()
    if len(parts) > 1 and parts[1]:
        for part in parts[1].split("&"):
            kv = part.split("=")  # handle trailing keyword query arguments without values
            if kv[0]:  # handle invalid keyword missing
                query[kv[0]] = kv[1] if len(kv) > 1 else None
    elif params:
        query = params
    request = DummyRequest(path=path, params=query)
    request.path_qs = request_path_query
    request.method = method
    request.content_type = content_type
    request.headers = headers or {}
    request.cookies = cookies or {}
    request.matched_route = None  # cornice method
    if content_type:
        request.headers["Content-Type"] = content_type
    request.body = body
    try:
        if body:
            # set missing DummyRequest.json attribute
            request.json = json_pkg.loads(body)
    except (TypeError, ValueError):
        pass
    request.registry.settings = settings or {}
    return request  # noqa  # fake type of what is normally expected just to avoid many 'noqa'


def test_request(test_item,             # type: AnyMagpieTestItemType
                 method,                # type: Str
                 path,                  # type: Str
                 data=None,             # type: Optional[Union[JSON, Str]]
                 json=None,             # type: Optional[Union[JSON, Str]]
                 body=None,             # type: Optional[Union[JSON, Str]]
                 params=None,           # type: Optional[Dict[Str, Str]]
                 timeout=10,            # type: int
                 retries=3,             # type: int
                 allow_redirects=True,  # type: bool
                 content_type=None,     # type: Optional[Str]
                 headers=None,          # type: Optional[HeadersType]
                 cookies=None,          # type: Optional[CookiesType]
                 **kwargs               # type: Any
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

    :param test_item: one of `BaseTestCase`, `webtest.TestApp` or remote server URL to call with `requests`
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
    :param retries: number of retry attempts in case the requested failed due to timeout (only when using URL).
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
        err_code = None
        err_msg = None
        try:
            resp = app_or_url._gen_request(method, path, **kwargs)  # pylint: disable=W0212  # noqa: W0212
        except AppError as exc:
            err_code = exc
            err_msg = str(exc)
        except HTTPException as exc:
            err_code = exc.status_code
            err_msg = str(exc) + str(getattr(exc, "exception", ""))
        except Exception as exc:
            err_code = 500
            err_msg = "Unknown: {!s}".format(exc)
        finally:
            if err_code:
                info = json_msg({"path": path, "method": method, "body": _body, "headers": kwargs["headers"]})
                result = "Request raised unexpected error: {!s}\nError: {}\nRequest:\n{}"
                raise AssertionError(result.format(err_code, err_msg, info))

        # automatically follow the redirect if any and evaluate its response
        max_redirect = kwargs.get("max_redirects", 5)
        while 300 <= resp.status_code < 400 and max_redirect > 0:  # noqa
            resp = resp.follow()
            max_redirect -= 1
        assert max_redirect >= 0, "Maximum follow redirects reached."
        # test status accordingly if specified
        assert resp.status_code == status or status is None, "Response not matching the expected status code."
        return resp

    kwargs.pop("expect_errors", None)  # remove keyword specific to TestApp
    content_type = get_header("Content-Type", headers)
    if json or content_type == CONTENT_TYPE_JSON:
        kwargs["json"] = _body
    elif data or body:
        kwargs["data"] = _body
    url = "{url}{path}".format(url=app_or_url, path=path)
    while True:
        try:
            return requests.request(method, url, params=params, headers=headers, cookies=cookies,
                                    timeout=timeout, allow_redirects=allow_redirects, **kwargs)
        except requests.exceptions.ReadTimeout:
            if retries <= 0:
                raise
            retries -= 1


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
        body = TestSetup.get_UserInfo(test_item, override_body=body)
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


def visual_repr(item):
    # type: (Any) -> Str
    try:
        if isinstance(item, (dict, list)):
            return json_pkg.dumps(item, indent=4, ensure_ascii=False)
    except Exception:
        pass
    return "'{}'".format(repr(item))


def format_test_val_ref(val, ref, pre="Fail", msg=None):
    if is_null(msg):
        _msg = "({}) Failed condition between test and reference values.".format(pre)
    else:
        _msg = "({}) Test value: {}, Reference value: {}".format(pre, visual_repr(val), visual_repr(ref))
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
    # type: (Collection[Any], Union[Collection[Any], NullType], Optional[Str], bool) -> None
    """
    :param iter_val: tested values.
    :param iter_ref: reference values.
    :param msg: override message to display if failing test.
    :param any_order: allow equal values to be provided in any order, otherwise order must match as well as values.
    :raises AssertionError:
        If all values in :paramref:`iter_val` are not equal to values within :paramref:`iter_ref`.
        If :paramref:`any_order` is ``False``, also raises if equal items are not in the same order.
    """
    r_val = repr(iter_val)
    r_ref = repr(iter_ref)
    assert all_equal(iter_val, iter_ref, any_order), format_test_val_ref(r_val, r_ref, pre="All Equal Fail", msg=msg)


def check_val_equal(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is not equal to :paramref:`ref`."""
    assert is_null(ref) or val == ref, format_test_val_ref(val, ref, pre="Equal Fail", msg=msg)


def check_val_not_equal(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is equal to :paramref:`ref`."""
    assert is_null(ref) or val != ref, format_test_val_ref(val, ref, pre="Not Equal Fail", msg=msg)


def check_val_is_in(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is not in to :paramref:`ref`."""
    assert is_null(ref) or val in ref, format_test_val_ref(val, ref, pre="Is In Fail", msg=msg)


def check_val_not_in(val, ref, msg=None):
    # type: (Any, Union[Any, NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is in to :paramref:`ref`."""
    assert is_null(ref) or val not in ref, format_test_val_ref(val, ref, pre="Not In Fail", msg=msg)


def check_val_type(val, ref, msg=None):
    # type: (Any, Union[Type[Any], NullType], Optional[Str]) -> None
    """:raises AssertionError: if :paramref:`val` is not an instanced of :paramref:`ref`."""
    assert isinstance(val, ref), format_test_val_ref(val, repr(ref), pre="Type Fail", msg=msg)


def check_raises(func, exception_type, msg=None):
    # type: (Callable[[], Any], Type[Exception], Optional[Str]) -> Exception
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
    # type: (Callable[[], Any], Optional[Str]) -> Any
    """
    Calls the callable and verifies that no exception was raised.

    :raise AssertionError: on any raised exception.
    """
    try:
        return func()
    except Exception as exc:  # pylint: disable=W0703
        msg = ": {}".format(msg) if msg else "."
        raise AssertionError("Exception [{!r}] was raised when none is expected{}".format(type(exc).__name__, msg))


def check_response_basic_info(response,                         # type: AnyResponseType
                              expected_code=200,                # type: int
                              expected_type=CONTENT_TYPE_JSON,  # type: Str
                              expected_method="GET",            # type: Str
                              extra_message=None,               # type: Optional[Str]
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
    :param extra_message: additional message to append to every specific test message if provided.
    :param version: perform conditional checks according to test instance version (default to latest if not provided).
    :return: json body of the response for convenience.
    """
    def _(_msg):
        return _msg + " " + extra_message if extra_message else _msg

    check_val_is_in("Content-Type", dict(response.headers), msg=_("Response doesn't define 'Content-Type' header."))
    content_types = get_response_content_types_list(response)
    check_val_is_in(expected_type, content_types, msg=_("Response doesn't match expected HTTP Content-Type header."))
    code_message = "Response doesn't match expected HTTP status code."
    if expected_type == CONTENT_TYPE_JSON:
        # provide more details about mismatching code since to help debug cause of error
        code_message += "\nReason:\n{}".format(json_msg(get_json_body(response)))
    check_val_equal(response.status_code, expected_code, msg=_(code_message))

    if expected_type == CONTENT_TYPE_JSON:
        body = get_json_body(response)
        check_val_is_in("code", body, msg=_("Parameter 'code' should be in response JSON body."))
        check_val_is_in("type", body, msg=_("Parameter 'type' should be in response JSON body."))
        check_val_is_in("detail", body, msg=_("Parameter 'detail' should be in response JSON body."))
        check_val_equal(body["code"], expected_code, msg=_("Parameter 'code' should match HTTP status code."))
        check_val_equal(body["type"], expected_type, msg=_("Parameter 'type' should match HTTP Content-Type header."))
        check_val_not_equal(body["detail"], "", msg=_("Parameter 'detail' should not be empty."))
    else:
        body = response.text

    if response.status_code >= 400:
        v2_and_up = not bool(version) or TestVersion(version) >= TestVersion("2")
        if not v2_and_up and response.status_code not in [401, 404, 500]:
            return body  # older API error response did not all have the full request details

        # error details available for any content-type, just in different format
        check_val_is_in("url" if v2_and_up else "request_url", body, msg=_("Request URL missing from contents,"))
        check_val_is_in("path" if v2_and_up else "route_name", body, msg=_("Request path missing from contents."))
        check_val_is_in("method", body, msg=_("Request method missing from contents."))
        if expected_type == CONTENT_TYPE_JSON:  # explicitly check by dict-key if JSON
            check_val_equal(body["method"], expected_method, msg=_("Request method not matching expected value."))

    return body


def check_ui_response_basic_info(response, expected_code=200, expected_type=CONTENT_TYPE_HTML,
                                 expected_title="Magpie Administration"):
    # type: (AnyResponseType, int, Str, Optional[Str]) -> Str
    """
    Validates minimal expected elements in a `Magpie` UI page.

    Number of validations is limited compared to API checks accomplished by :func:`check_response_basic_info`.
    That function should therefore be employed for responses coming directly from the API routes.

    :raises AssertionError: if any of the expected validation elements does not meet requirement.
    :returns: HTML text body of the response if every check was successful.
    """
    msg = None \
        if get_header("Content-Type", response.headers) != CONTENT_TYPE_JSON \
        else "Response body: {}".format(get_json_body(response))
    check_val_equal(response.status_code, expected_code, msg=msg)
    check_val_is_in("Content-Type", dict(response.headers))
    check_val_is_in(expected_type, get_response_content_types_list(response))
    if expected_title:
        check_val_is_in(expected_title, response.text, msg=null)   # don't output big html if failing
    return response.text


def check_error_param_structure(body,                                   # type: JSON
                                version=null,                           # type: Optional[Str]
                                param_value=null,                       # type: Optional[Any]
                                param_name=null,                        # type: Optional[Str]
                                param_compare=null,                     # type: Optional[Any]
                                is_param_value_literal_unicode=False,   # type: bool
                                param_name_exists=False,                # type: bool
                                param_compare_exists=False,             # type: bool
                                ):                                      # type: (...) -> None
    """
    Validates error response ``param`` information based on different Magpie version formats.

    :param body: JSON body of the response to validate.
    :param version: explicit Magpie version to use for validation, or the current package version if ``null``.
    :param param_value:
        Expected 'value' of param the parameter.
        Contained field value not verified if ``null``, only presence of the field.
    :param param_name:
        Expected 'name' of param. Ignored for older Magpie version that did not provide this information.
        Contained field value not verified if ``null`` and ``param_name_exists`` is ``True`` (only its presence).
        If provided, automatically implies ``param_name_exists=True``. Skipped otherwise.
    :param param_compare:
        Expected 'compare'/'param_compare' value (filed name according to version)
        Contained field value not verified if ``null`` and ``param_compare_exists`` is ``True`` (only its presence).
        If provided, automatically implies ``param_compare_exists=True``. Skipped otherwise.
    :param is_param_value_literal_unicode: param value is represented as `u'{paramValue}'` for older Magpie version.
    :param param_name_exists: verify that 'name' is in the body, not validating its value.
    :param param_compare_exists: verify that 'compare'/'param_compare' is in the body, not validating its value.
    :raises AssertionError: on any failing condition
    """
    check_val_type(body, dict)
    check_val_is_in("param", body)
    version = version or __meta__.__version__
    if TestVersion(version) >= TestVersion("0.6.3"):
        check_val_type(body["param"], dict)
        check_val_is_in("value", body["param"])
        if param_name_exists or param_name is not null:
            check_val_is_in("name", body["param"])
            if param_name is not null:
                check_val_equal(body["param"]["name"], param_name)
        if param_value is not null:
            check_val_equal(body["param"]["value"], param_value)
        if param_compare_exists or param_compare is not null:
            check_val_is_in("compare", body["param"])
            if param_compare is not null:
                check_val_equal(body["param"]["compare"], param_compare)
    else:
        if param_value is not null:
            # unicode representation was explicitly returned in value only when of string type
            if is_param_value_literal_unicode and isinstance(param_value, six.string_types):
                param_value = u"u\'{}\'".format(param_value)
            check_val_equal(body["param"], param_value)
        if param_compare_exists or param_compare is not null:
            check_val_is_in("param_compare", body)
            if param_compare is not null:
                check_val_equal(body["param_compare"], param_compare)


class TestSetup(object):
    """
    Generic setup and validation methods across unittests.

    This class offers a large list of commonly reusable operations to setup or cleanup test cases.

    All methods take as input an instance of a `Test Case` derived from :class:`BaseTestCase` (or directly a
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
        employed by default. Refer to :attr:`BaseTestCase.cookies` and :attr:`BaseTestCase.json_headers`
        (N.B.: headers with extended JSON content-type for simplified API response body parsing). Checks that point at
        UI pages could do otherwise (e.g.: method :meth:`check_UpStatus`).

    .. warning::
        The utility methods can also be used directly with a :class:`TestApp` **IF** all required ``test_`` attributes
        for the given method are overridden with their respective arguments, since ``test_`` members will be missing.
        If a `Test Case` object is available, it should be used instead to let methods find every parameter.
    """
    # pylint: disable=C0103,invalid-name

    @staticmethod
    def get_Version(test_case, real_version=False, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, bool, Optional[HeadersType], Optional[CookiesType]) -> Str
        """
        Obtains the `Magpie` version of the test instance (local or remote). This version can then be used in
        combination with :class:`TestVersion` comparisons or :func:`warn_version` to toggle test execution of certain
        test cases that have version-dependant format, conditions or feature changes.

        This is useful *mostly* for remote server tests which could be out-of-sync compared to the current source code.
        It provides some form of backward compatibility with older instances provided that tests are updated accordingly
        when new features or changes are applied, which adds modifications to previously existing test methodologies or
        results.

        .. seealso::
            - :func:`warn_version`

        :param real_version:
            Force request to retrieve the API version as defined in metadata.
            Otherwise, version can be either overridden by ``MAGPIE_TEST_VERSION``, the current Test Suite, or the API
            version, whichever is found first.
        :param override_headers: headers for request to override any stored ones from Test Suite.
        :param override_cookies: cookies for request to override any stored ones from Test Suite.
        :raises AssertionError: if the response cannot successfully retrieve the test instance version.
        """
        if not real_version:
            version = get_constant("MAGPIE_TEST_VERSION")
            if version:
                return version
            version = getattr(test_case, "version", None)
            if version:
                return version
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
        Verifies that the Magpie UI page at very least returned an HTTP Ok response with the displayed title. Validates
        that at the bare minimum, no underlying internal error occurred from the API or UI calls.

        .. warning::
            Because this check is accomplished via the UI interface, :attr:`BaseTestCase.test_cookies` and
            :attr:`BaseTestCase.headers` attributes are used instead of admin-level ones as in other methods
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
                         form_match,                        # type: Union[Str, int, Dict[Str, Str], Form]
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

        .. code-block:: python

            svc_resp = check_FormSubmit(test, form_match="goto_add_service", path="/ui/services")
            add_resp = check_FormSubmit(test, form_match="add_service", form_data={...}, previous_response=svc_resp)

        :param test_case: `Test Case` to retrieve the instance and parameters to send requests to.
        :param form_match:
            Can be a form name, the form index (from all available forms on page) or an
            iterable of key/values of form fields to search for a match (first match is used if many are available).
            Also, can be directly the targeted form if already retrieved from the previous response.
        :param form_data:
            Specifies matched form fields to be filled as if entered from UI input using given key/value.
            If multiple fields share the same key, the value must provide an iterable of same length as the expected
            amount of fields matching that key, to fill each of the individual value.
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
        if isinstance(form_match, Form):
            form = form_match
        elif isinstance(form_match, (int, six.string_types)):
            form = resp.forms[form_match]
        else:
            # select form if all key/value pairs specified match the current one
            for f in resp.forms.values():
                f_fields = [(fk, fv[0].value) for fk, fv in f.fields.items()]
                if all((mk, mv) in f_fields for mk, mv in form_match.items()):
                    form = f
                    break
        if not form:
            available_forms = {fm: {fk: fv[0].value for fk, fv in f.fields.items()} for fm, f in resp.forms.items()}
            available_forms = json_msg(available_forms)
            test_case.fail("could not find requested form for submission "
                           "[form_match: {!r}, form_submit: {!r}, form_data: {!r}] "
                           .format(form_match, form_submit, form_data) +
                           "from available form match/data combinations: [{}]".format(available_forms))
        if form_data:
            for f_field, f_value in dict(form_data).items():
                if isinstance(f_value, (list, set, tuple)):
                    for i, i_value in enumerate(f_value):
                        form.set(f_field, i_value, i)
                else:
                    form[f_field] = f_value

        resp = form.submit(form_submit, expect_errors=expect_errors)
        while 300 <= resp.status_code < 400 and max_redirect > 0:
            resp = resp.follow()
        # basic validation of UI response, but ignore title because it is irrelevant during form validation
        check_ui_response_basic_info(
            resp, expected_code=expected_code, expected_type=expected_type, expected_title=None
        )
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
        if path.startswith("/ui"):
            check_ui_response_basic_info(resp, expected_code=401, expected_type=expected_type)
            if expected_type == CONTENT_TYPE_JSON:
                return get_json_body(resp)
            return resp.text
        return check_response_basic_info(resp, expected_code=401, expected_type=expected_type, expected_method=method)

    @staticmethod
    def check_ResourceStructure(test_case,                      # type: AnyMagpieTestCaseType
                                body,                           # type: JSON
                                resource_name,                  # type: Str
                                resource_type,                  # type: Str
                                resource_display_name=null,     # type: Str
                                ):                              # type: (...) -> None
        """
        Validates :term:`Resource` basic information (not checking children) based on different Magpie version formats.

        :param test_case: test container
        :param body: JSON body of the response to validate.
        :param resource_name: name of the resource to validate.
        :param resource_type: type of the resource to validate.
        :param resource_display_name: display name of the resource to validate.
        :raises AssertionError: failing condition
        """
        if TestVersion(test_case.version) >= TestVersion("0.6.3"):
            if resource_display_name is null:
                resource_display_name = resource_name
            check_val_is_in("resource", body)
            check_val_type(body["resource"], dict)
            check_val_is_in("resource_name", body["resource"])
            check_val_is_in("resource_display_name", body["resource"])
            check_val_is_in("resource_type", body["resource"])
            check_val_is_in("resource_id", body["resource"])
            check_val_equal(body["resource"]["resource_name"], resource_name)
            check_val_equal(body["resource"]["resource_display_name"], resource_display_name)
            check_val_equal(body["resource"]["resource_type"], resource_type)
            check_val_type(body["resource"]["resource_id"], int)
        else:
            check_val_is_in("resource_name", body)
            check_val_is_in("resource_type", body)
            check_val_is_in("resource_id", body)
            check_val_equal(body["resource_name"], resource_name)
            check_val_equal(body["resource_type"], resource_type)
            check_val_type(body["resource_id"], int)

    @staticmethod
    def check_ResourceChildren(test_case,           # type: AnyMagpieTestCaseType
                               resource_children,   # type: JSON
                               parent_resource_id,  # type: int
                               root_service_id,     # type: int
                               ):                   # type: (...) -> None
        """
        Crawls through a :paramref:`resource_children` tree (potentially multi-level) to recursively validate data
        field, types and corresponding values.

        :param test_case: test container
        :param resource_children: top-level 'resources' dictionary possibly also containing children resources.
        :param parent_resource_id: top-level resource/service ID
        :param root_service_id: top-level service ID
        :raises AssertionError: any invalid match on expected data field, type or value
        """
        check_val_type(resource_children, dict)
        for resource_id in resource_children:
            check_val_type(resource_id, six.string_types)
            resource_int_id = int(resource_id)  # should by an 'int' string, no error raised
            resource_info = resource_children[resource_id]
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
            TestSetup.check_ResourceChildren(test_case, resource_info["children"], resource_int_id, root_service_id)

    @staticmethod
    def check_ServiceFormat(test_case,                      # type: AnyMagpieTestCaseType
                            service,                        # type: JSON
                            override_permissions=null,      # type: Optional[Iterable[Str]]
                            skip_permissions=False,         # type: bool
                            has_children_resources=True,    # type: bool
                            has_private_url=True,           # type: bool
                            ):                              # type: (...) -> None
        """
        Validates the format structure of the :paramref:`service` container details.

        :param test_case: test container
        :param service: service body to be evaluated
        :param override_permissions:
            If not provided, validate permission name values to contain *all* permissions defined by the
            reference service's implementation in :mod:`magpie.services`.
            Otherwise, permissions are validated against the provided values.
        :param skip_permissions:
            Completely ignore checking the values contained in permissions (field presence and format still validated).
            Enforced to ``False```if :paramref:`override_permissions` is provided.
        :param has_children_resources:
            If ``True`` (default), also recursively validate the children resources of the :paramref:`service` using
            :meth:`TestSetup.check_ResourceChildren` to validate their expected format. In the case the service has no
            children resource, only validate the ``resources`` field and empty dictionary.
        :param has_private_url:
            If ``True`` (default), validates that the ``service_url`` field is displayed in the body accordingly.

        :raises AssertionError: any invalid match on expected data field, type or value
        """
        check_val_type(service, dict)
        check_val_is_in("resource_id", service)
        check_val_is_in("service_name", service)
        check_val_is_in("service_type", service)
        check_val_is_in("public_url", service)
        check_val_is_in("permission_names", service)
        check_val_type(service["resource_id"], int)
        check_val_type(service["service_name"], six.string_types)
        check_val_type(service["service_type"], six.string_types)
        check_val_type(service["public_url"], six.string_types)
        check_val_type(service["permission_names"], list)
        svc_res_id = service["resource_id"]
        if TestVersion(test_case.version) >= TestVersion("0.7.0"):
            check_val_is_in("service_sync_type", service)
            check_val_type(service["service_sync_type"], OPTIONAL_STRING_TYPES)
        if has_private_url:
            check_val_is_in("service_url", service)
            check_val_type(service["service_url"], six.string_types)
        elif not has_private_url and TestVersion(test_case.version) >= TestVersion("0.7.0"):
            check_val_not_in("service_url", service,
                             msg="Services under user routes shouldn't show private url.")
        if TestVersion(test_case.version) >= TestVersion("2.0.0"):
            if not skip_permissions or override_permissions is not null:
                if override_permissions is null:
                    check_val_not_equal(len(service["permission_names"]), 0,
                                        msg="Service-scoped route must always provide all allowed permissions.")
                    permissions = SERVICE_TYPE_DICT[service["service_type"]].permissions
                    if TestVersion(test_case.version) < TestVersion("3.0"):
                        override_permissions = [perm.value for perm in permissions]
                    else:
                        override_permissions = TestSetup.get_PermissionNames(test_case, permissions, combinations=True)
                else:
                    override_permissions = TestSetup.get_PermissionNames(test_case, override_permissions)
                check_all_equal(service["permission_names"], override_permissions, any_order=True)
        if has_children_resources:
            check_val_is_in("resources", service)
            children = service["resources"]
            TestSetup.check_ResourceChildren(test_case, children, svc_res_id, svc_res_id)
        else:
            check_val_not_in("resources", service)
            check_val_not_in("children", service)

    @staticmethod
    def get_AnyServiceOfTestServiceType(test_case,                      # type: AnyMagpieTestCaseType
                                        override_service_type=null,     # type: Optional[Str]
                                        override_headers=null,          # type: Optional[HeadersType]
                                        override_cookies=null,          # type: Optional[CookiesType]
                                        ):                              # type: (...) -> JSON
        """
        Obtains the first service from all available services that match the test service type.

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
        """
        Creates the test resource nested *immediately* under the test service. Test service *must* exist beforehand.

        :raises AssertionError: if the response correspond to failure to create the test resource.
        """
        app_or_url = get_app_or_url(test_case)
        svc_name = override_service_name if override_service_name is not null else test_case.test_service_name
        TestSetup.create_TestService(test_case, override_service_name=svc_name)
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
        """
        Creates the test resource nested *immediately* under the parent resource ID.

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
    def update_TestAnyResourcePermission(test_case,                         # type: AnyMagpieTestCaseType
                                         item_type,                         # type: Str
                                         method,                            # type: Str  # POST|PUT|DELETE
                                         override_item_name=null,           # type: Optional[Str]
                                         resource_info=null,                # type: Optional[JSON]
                                         override_resource_id=null,         # type: Optional[int]
                                         override_permission=null,          # type: Optional[AnyPermissionType]
                                         override_headers=null,             # type: Optional[HeadersType]
                                         override_cookies=null,             # type: Optional[CookiesType]
                                         ):                                 # type: (...) -> JSON
        """
        See :meth:`create_TestGroupResourcePermission` and :meth:`create_TestUserResourcePermission` for specific uses.
        """
        method = method.upper()
        if resource_info is null:
            resource_info = TestSetup.get_ResourceInfo(test_case, resource_id=override_resource_id, full_detail=True,
                                                       override_headers=override_headers,
                                                       override_cookies=override_cookies)
        else:
            no_perms = "permission_names" not in resource_info or not resource_info.get("permission_names")
            get_details = no_perms or override_permission is null
            resource_info = TestSetup.get_ResourceInfo(test_case, override_body=resource_info, full_detail=get_details,
                                                       override_headers=override_headers,
                                                       override_cookies=override_cookies)
        res_id = resource_info["resource_id"]
        if override_permission is null:
            # to preserve backward compatibility with existing tests that assumed first permission from different order,
            # override the modifiers to generate ([first-name]-allow-recursive) which was then returned as first element
            # (sorting of PermissionSet now returns MATCH before RECURSIVE)
            first_perm = resource_info["permission_names"][0]
            override_permission = PermissionSet(first_perm, access=Access.ALLOW, scope=Scope.RECURSIVE)
        if item_type == "group":
            item_name = override_item_name if override_item_name is not null else test_case.test_group_name
            item_path = "/groups/{}".format(item_name)
        elif item_type == "user":
            item_name = override_item_name if override_item_name is not null else test_case.test_user_name
            item_path = "/users/{}".format(item_name)
        else:
            raise ValueError("invalid item-type: [{}]".format(item_type))
        data = {"permission": PermissionSet(override_permission).json()}
        path = "{}/resources/{}/permissions".format(item_path, res_id)
        resp = test_request(test_case, method, path, data=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        if method == "DELETE":
            code = 200 if resp.status_code != 404 else 404
            return check_response_basic_info(resp, code, expected_method=method)
        return check_response_basic_info(resp, 201, expected_method=method)

    @staticmethod
    def create_TestUserResourcePermission(test_case,                        # type: AnyMagpieTestCaseType
                                          resource_info=null,               # type: Optional[JSON]
                                          override_resource_id=null,        # type: Optional[int]
                                          override_permission=null,         # type: Optional[AnyPermissionType]
                                          override_user_name=null,          # type: Optional[Str]
                                          override_headers=null,            # type: Optional[HeadersType]
                                          override_cookies=null,            # type: Optional[CookiesType]
                                          ):                                # type: (...) -> JSON
        """
        Utility method to create a permission on given resource for the user.

        Employs the resource information returned from one of the creation utilities:
            - :meth:`create_TestResource`
            - :meth:`create_TestService`
            - :meth:`create_TestServiceResource`

        If resource information container is not provided, all desired values must be given as parameter for creation.
        """
        return TestSetup.update_TestAnyResourcePermission(
            test_case, "user", "POST", resource_info=resource_info,
            override_resource_id=override_resource_id, override_permission=override_permission,
            override_item_name=override_user_name, override_headers=override_headers, override_cookies=override_cookies
        )

    @staticmethod
    def create_TestGroupResourcePermission(test_case,                        # type: AnyMagpieTestCaseType
                                           resource_info=null,               # type: Optional[JSON]
                                           override_resource_id=null,        # type: Optional[int]
                                           override_permission=null,         # type: Optional[AnyPermissionType]
                                           override_group_name=null,         # type: Optional[Str]
                                           override_headers=null,            # type: Optional[HeadersType]
                                           override_cookies=null,            # type: Optional[CookiesType]
                                           ):                                # type: (...) -> JSON
        """
        Utility method to create a permission on given resource for the group.

        Employs the resource information returned from one of the creation utilities:
            - :meth:`create_TestResource`
            - :meth:`create_TestService`
            - :meth:`create_TestServiceResource`

        If resource information container is not provided, all desired values must be given as parameter for creation.
        """
        return TestSetup.update_TestAnyResourcePermission(
            test_case, "group", "POST", resource_info=resource_info,
            override_resource_id=override_resource_id, override_permission=override_permission,
            override_item_name=override_group_name, override_headers=override_headers, override_cookies=override_cookies
        )

    @staticmethod
    def get_PermissionNames(test_case,              # type: AnyMagpieTestCaseType
                            permissions,            # type: Union[AnyPermissionType, Collection[AnyPermissionType]]
                            combinations=False,     # type: bool
                            ):                      # type: (...) -> List[Str]
        """
        Obtains all applicable permission names for the given version and specified permission(s).

        :param test_case: test case
        :param permissions: one or many permission(s) for which to generate the list of applicable permission names.
        :param combinations: extend permissions with all possible modifiers, applicable only if version allows it.
        """
        version = TestSetup.get_Version(test_case)
        if not isinstance(permissions, (list, set, tuple)):
            permissions = [permissions]
        if combinations and TestVersion(version) >= TestVersion("3.0"):
            permissions = [PermissionSet(*perm_combo) for perm_combo in itertools.product(permissions, Access, Scope)]
        else:
            permissions = [PermissionSet(perm) for perm in permissions]
        perm_names = set()
        for permission in permissions:
            perm_impl = permission.implicit_permission
            if perm_impl is not None:
                perm_names.add(perm_impl)
            if TestVersion(version) >= TestVersion("3.0"):
                perm_names.add(permission.explicit_permission)
        return list(perm_names)

    @staticmethod
    def get_ResourceInfo(test_case,                 # type: AnyMagpieTestCaseType
                         override_body=None,        # type: Optional[JSON]
                         full_detail=False,         # type: bool
                         resource_id=None,          # type: Optional[int]
                         override_headers=null,     # type: Optional[HeadersType]
                         override_cookies=null,     # type: Optional[CookiesType]
                         ):                         # type: (...) -> JSON
        """
        Obtains in a backward compatible way the resource details based on resource or service response body and the
        tested instance version.

        Alternatively to :paramref:`body`, one can directly fetch details from provided :paramref:`resource_id`.
        Otherwise, if :paramref:`body` was provided and :paramref:`full_detail` is requested, executes another request
        to obtain the additional information with inferred resource ID available from the body. This obtains additional
        details resource such as applicable permissions that are not available from base request body returned at
        resource creation. This is essentially the same as requesting the details directly with :paramref:`resource_id`.
        """
        body = override_body
        if override_body:
            if TestVersion(test_case.version) >= TestVersion("0.6.3"):
                # skip if sub-element was already extracted and provided as input override_body
                if "resource_id" not in body:
                    body = body.get("resource") or body.get("service")
                    check_val_type(body, dict)
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
        """
        Obtains test service details.

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
        if TestVersion(test_case.version) < TestVersion("0.9.1"):
            svc_getter = svc_name
        return json_body[svc_getter]

    @staticmethod
    def get_TestServiceDirectResources(test_case,                       # type: AnyMagpieTestCaseType
                                       ignore_missing_service=False,    # type: bool
                                       override_service_name=null,      # type: Optional[Str]
                                       override_headers=null,           # type: Optional[HeadersType]
                                       override_cookies=null,           # type: Optional[CookiesType]
                                       ):                               # type: (...) -> List[JSON]
        """
        Obtains test resources nested *immediately* under test service.

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
        """
        Validates that test resource nested *immediately* under test service does not exist.

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
        """
        Deletes the test resource under test service.

        If the resource does not exist, skip. Otherwise, delete it and validate that it was indeed removed.

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
        """
        Creates the test service.

        If the service already exists, deletes it. Then, attempts creation.

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
        if svc_name:
            test_case.extra_service_names.add(svc_name)  # indicate potential removal at a later point
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
            if TestVersion(test_case.version) < TestVersion("0.9.1"):
                body.update({"service": body[svc_name]})
                body.pop(svc_name)
            return body
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def check_NonExistingTestService(test_case, override_service_name=null):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """
        Validates that the test service does not exist.

        :raises AssertionError: if the response does not correspond to missing service.
        """
        services_info = TestSetup.get_RegisteredServicesList(test_case)
        services_names = [svc["service_name"] for svc in services_info]
        service_name = override_service_name if override_service_name is not null else test_case.test_service_name
        check_val_not_in(service_name, services_names)

    @staticmethod
    def delete_TestService(test_case, override_service_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """
        Deletes the test service.

        If the service does not exist, skip operation. Otherwise, proceed to remove it and validate its removal.

        :raises AssertionError: if the response does not correspond to successful validation or removal of the service.
        """
        app_or_url = get_app_or_url(test_case)
        service_name = override_service_name if override_service_name is not null else test_case.test_service_name
        services_info = TestSetup.get_RegisteredServicesList(test_case,
                                                             override_headers=override_headers,
                                                             override_cookies=override_cookies)
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
        """
        Obtains the list of registered services names.

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
        """
        Deletes the test resource directly using its ID.

        If the resource does not exists, skips the operation. Otherwise, delete it and validate its removal.

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
        """
        Obtains the list of registered users.

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
        """
        Ensures that the test user does not exist.

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
        """
        Creates the test user.

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
        usr_name = (data or {}).get("user_name")
        if usr_name:
            test_case.extra_user_names.add(usr_name)  # indicate potential removal at a later point
        resp = test_request(app_or_url, "POST", "/users", json=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def delete_TestUser(test_case, override_user_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """
        Ensures that the test user does not exist.

        If the user does not exist, skip the operation. Otherwise, delete it and validate its removal.

        :raises AssertionError: if any request response does not match successful validation or removal from group.
        """
        app_or_url = get_app_or_url(test_case)
        headers = override_headers if override_headers is not null else test_case.json_headers
        cookies = override_cookies if override_cookies is not null else test_case.cookies
        users = TestSetup.get_RegisteredUsersList(test_case, override_headers=headers, override_cookies=cookies)
        user_name = override_user_name if override_user_name is not null else test_case.test_user_name
        # delete as required, skip if non-existing
        if user_name in users:
            path = "/users/{usr}".format(usr=user_name)
            resp = test_request(app_or_url, "DELETE", path, headers=headers, cookies=cookies)
            check_response_basic_info(resp, 200, expected_method="DELETE")
        TestSetup.check_NonExistingTestUser(test_case, override_user_name=user_name,
                                            override_headers=headers, override_cookies=cookies)

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
        Using :paramref:`override_body`, details can be fetched from JSON body instead of performing the request.
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
        version = override_version if override_version is not null else TestSetup.get_Version(test_case)
        if TestVersion(version) >= TestVersion("0.6.3"):
            check_val_is_in("user", body)
            body = body["user"]
        return body or {}

    @staticmethod
    def get_GroupInfo(test_case,                 # type: AnyMagpieTestCaseType
                      override_body=None,        # type: JSON
                      override_group_name=null,  # type: Optional[Str]
                      override_version=null,     # type: Optional[Str]
                      override_headers=null,     # type: Optional[HeadersType]
                      override_cookies=null,     # type: Optional[CookiesType]
                      ):                         # type: (...) -> JSON
        """
        Obtains in a backward compatible way the group details based on response body and the tested instance version.

        Executes an HTTP request with required admin-level login cookies/headers if the details are not found.
        Using :paramref:`override_body`, details can be fetched from JSON body instead of performing the request.
        Employed version is extracted from the :paramref:`test_case` unless provided by :paramref:`override_version`.
        """
        version = override_version if override_version is not null else TestSetup.get_Version(test_case)
        grp_name = override_group_name if override_group_name is not null else test_case.test_group_name
        if TestVersion(version) < TestVersion("0.6.4"):  # route did not exist before that
            if override_body and "group" in override_body:
                return override_body["group"]
            if override_body and "group_name" in override_body:
                return override_body
            return {"group_name": grp_name or {}}
        if override_body:
            if override_body and "group" in override_body:
                return override_body["group"]
            if override_body and "group_name" in override_body:
                return override_body
        resp = test_request(test_case, "GET", "/groups/{}".format(grp_name),
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        body = check_response_basic_info(resp)
        check_val_is_in("group", body)
        return body["group"] or {}

    @staticmethod
    def check_UserGroupMembership(test_case,                    # type: AnyMagpieTestCaseType
                                  member=True,                  # type: bool
                                  override_user_name=null,      # type: Optional[Str]
                                  override_group_name=null,     # type: Optional[Str]
                                  override_headers=null,        # type: Optional[HeadersType]
                                  override_cookies=null,        # type: Optional[CookiesType]
                                  ):                            # type: (...) -> None
        """
        Ensures that the test user is a member or not of the test group (according to :paramref:`member` value).

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
        """
        Ensures that the test user is a member of the test group, adding him to the group as needed.

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
            resp = test_request(app_or_url, "POST", path, json=data,
                                headers=override_headers if override_headers is not null else test_case.json_headers,
                                cookies=override_cookies if override_cookies is not null else test_case.cookies)
            check_response_basic_info(resp, 201, expected_method="POST")
        TestSetup.check_UserGroupMembership(test_case, override_user_name=usr_name, override_group_name=grp_name,
                                            override_headers=override_headers, override_cookies=override_cookies)

    @staticmethod
    def get_RegisteredGroupsList(test_case, only_discoverable=False, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, bool, Optional[HeadersType], Optional[CookiesType]) -> List[Str]
        """
        Obtains all existing group names, or optionally, only return the publicly discoverable ones.

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
        """
        Validate that test group does not exist.

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
        """
        Create the test group.

        :raises AssertionError: if the request does not have expected response matching successful creation.
        """
        app_or_url = get_app_or_url(test_case)
        data = override_data
        if override_data is null:
            data = {"group_name": override_group_name if override_group_name is not null else test_case.test_group_name}
            # only add 'discoverable' if explicitly provided here to preserve original behaviour of 'no value provided'
            if override_discoverable is not null:
                data["discoverable"] = override_discoverable
        grp_name = (data or {}).get("group_name")
        if grp_name:
            test_case.extra_group_names.add(grp_name)  # indicate potential removal at a later point
        resp = test_request(app_or_url, "POST", "/groups", json=data,
                            headers=override_headers if override_headers is not null else test_case.json_headers,
                            cookies=override_cookies if override_cookies is not null else test_case.cookies)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def delete_TestGroup(test_case, override_group_name=null, override_headers=null, override_cookies=null):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[HeadersType], Optional[CookiesType]) -> None
        """
        Delete the test group.

        Skip operation if the group does not exist. Otherwise, proceed to delete it and validate its removal.

        :raises AssertionError: if the request does not have expected response matching successful deletion.
        :return: nothing. Group is ensured to not exist.
        """
        app_or_url = get_app_or_url(test_case)
        headers = override_headers if override_headers is not null else test_case.json_headers
        cookies = override_cookies if override_cookies is not null else test_case.cookies
        groups = TestSetup.get_RegisteredGroupsList(test_case, override_headers=headers, override_cookies=cookies)
        group_name = override_group_name if override_group_name is not null else test_case.test_group_name
        # delete as required, skip if non-existing
        if group_name in groups:
            path = "/groups/{grp}".format(grp=group_name)
            resp = test_request(app_or_url, "DELETE", path, headers=headers, cookies=cookies)
            check_response_basic_info(resp, 200, expected_method="DELETE")
        TestSetup.check_NonExistingTestGroup(test_case, override_group_name=group_name,
                                             override_headers=headers, override_cookies=cookies)

    @staticmethod
    def delete_TestUserResourcePermission(test_case,                        # type: AnyMagpieTestCaseType
                                          resource_info=null,               # type: Optional[JSON]
                                          override_resource_id=null,        # type: Optional[int]
                                          override_permission=null,         # type: Optional[AnyPermissionType]
                                          override_user_name=null,          # type: Optional[Str]
                                          override_headers=null,            # type: Optional[HeadersType]
                                          override_cookies=null,            # type: Optional[CookiesType]
                                          ignore_missing=True,              # type: bool
                                          ):                                # type: (...) -> JSON
        """
        Utility method to delete a permission on given resource for the user.

        Employs the resource information returned from one of the creation utilities:
            - :meth:`create_TestResource`
            - :meth:`create_TestService`
            - :meth:`create_TestServiceResource`

        If resource information container is not provided, the resource ID must be given as parameter for deletion.
        If the permission cannot be found, the operation assumes that nothing needs to be done (no failure).
        """
        result = TestSetup.update_TestAnyResourcePermission(
            test_case, "user", "DELETE", resource_info=resource_info,
            override_resource_id=override_resource_id, override_permission=override_permission,
            override_item_name=override_user_name, override_headers=override_headers, override_cookies=override_cookies
        )
        if not ignore_missing:
            check_val_equal(result["code"], 200)
        return result

    @staticmethod
    def delete_TestGroupResourcePermission(test_case,                        # type: AnyMagpieTestCaseType
                                           resource_info=null,               # type: Optional[JSON]
                                           override_resource_id=null,        # type: Optional[int]
                                           override_permission=null,         # type: Optional[AnyPermissionType]
                                           override_group_name=null,         # type: Optional[Str]
                                           override_headers=null,            # type: Optional[HeadersType]
                                           override_cookies=null,            # type: Optional[CookiesType]
                                           ignore_missing=True,              # type: bool
                                           ):                                # type: (...) -> JSON
        """
        Utility method to delete a permission on given resource for the group.

        Employs the resource information returned from one of the creation utilities:
            - :meth:`create_TestResource`
            - :meth:`create_TestService`
            - :meth:`create_TestServiceResource`

        If resource information container is not provided, the resource ID must be given as parameter for deletion.
        If the permission cannot be found, the operation assumes that nothing needs to be done (no failure).
        """
        result = TestSetup.update_TestAnyResourcePermission(
            test_case, "group", "DELETE", resource_info=resource_info,
            override_resource_id=override_resource_id, override_permission=override_permission,
            override_item_name=override_group_name, override_headers=override_headers, override_cookies=override_cookies
        )
        if not ignore_missing:
            check_val_equal(result["code"], 200)
        return result
