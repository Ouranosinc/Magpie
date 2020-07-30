import json
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
    get_settings_from_config_ini
)

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from tests.interfaces import Base_Magpie_TestCase  # noqa: F401
    from typing import Any, Callable, Dict, Iterable, List, NoReturn, Optional, Tuple, Type, Union  # noqa: F401
    from magpie.typedefs import (  # noqa: F401
        AnyCookiesType, AnyHeadersType, AnyResponseType, AnyValue, CookiesType, HeadersType, JSON, SettingsType, Str
    )
    # pylint: disable=C0103,invalid-name
    OptionalHeaderCookiesType = Tuple[Optional[AnyHeadersType], Optional[AnyCookiesType]]
    OptionalStringType = six.string_types + tuple([type(None)])
    TestAppOrUrlType = Union[Str, TestApp]
    AnyMagpieTestCaseType = Union[Type[Base_Magpie_TestCase], Base_Magpie_TestCase]
    AnyMagpieTestItemType = Union[AnyMagpieTestCaseType, TestAppOrUrlType]


class RunOption(object):
    __slots__ = ["_name", "_enabled", "_marker"]

    def __init__(self, name, marker=None):
        self._name = name
        self._marker = marker if marker else name.lower().replace("magpie_test_", "")
        self._enabled = self._default_run()

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
    Decorates the test/class with ``pytest.mark`` and ``unittest.skipUnless`` using the provided test condition
    represented by the given ``RunOption``.

    Allows to decorate a function or class such that::

        option = make_run_option_decorator(RunOption("MAGPIE_TEST_CUSTOM_MARKER"))

        @option
        def test_func():
            <test>

    is equivalent to::

        @pytest.mark.custom_marker
        @unittest.skipUnless(runner.MAGPIE_TEST_CUSTOM_MARKER, reason="...")
        def test_func():
            <test>

    All ``<custom_marker>`` definitions should be added to ``setup.cfg``.
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
    def __new__(cls, name):
        return make_run_option_decorator(RunOption(name))


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
    """Obtains the referenced Magpie local application or remote URL from Test Suite implementation."""
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
    return [ct.strip() for ct in response.headers["Content-Type"].split(";")]


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


def test_request(test_item, method, path, timeout=5, allow_redirects=True, **kwargs):
    # type: (AnyMagpieTestItemType, Str, Str, int, bool, Any) -> AnyResponseType
    """
    Calls the request using either a :class:`webtest.TestApp` instance or :class:`requests.Request` from a string URL.

    :param test_item: one of `Base_Magpie_TestCase`, `webtest.TestApp` or remote server URL to call with `requests`
    :param method: request method (GET, POST, PUT, DELETE)
    :param path: test path starting at base path
    :param timeout: `timeout` to pass down to `request`
    :param allow_redirects: `allow_redirects` to pass down to `request`
    :return: response of the request
    """
    method = method.upper()
    status = kwargs.pop("status", None)

    # obtain json body from any json/data/body/params kw and empty {} if not specified
    # reapply with the expected webtest/requests method kw afterward
    json_body = None
    for kw in ["json", "data", "body", "params"]:
        json_body = kwargs.get(kw, json_body)
        if kw in kwargs:
            kwargs.pop(kw)
    json_body = json_body or {}

    app_or_url = get_app_or_url(test_item)
    if isinstance(app_or_url, TestApp):
        # remove any 'cookies' keyword handled by the 'TestApp' instance
        if "cookies" in kwargs:
            cookies = kwargs.pop("cookies")
            if cookies and not app_or_url.cookies:
                app_or_url.cookies.update(cookies)

        # obtain Content-Type header if specified to ensure it is properly applied
        kwargs["content_type"] = get_header("Content-Type", kwargs.get("headers"))

        # convert JSON body as required
        kwargs["params"] = json_body
        if json_body is not None:
            kwargs.update({"params": json.dumps(json_body, cls=json.JSONEncoder)})
        if status and status >= 300:
            kwargs.update({"expect_errors": True})
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

    # remove keywords specific to TestApp
    kwargs.pop("expect_errors", None)

    kwargs["json"] = json_body
    url = "{url}{path}".format(url=app_or_url, path=path)
    return requests.request(method, url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)


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
                resp_cookies = app_or_url.cookies    # automatically set by form submit
            else:
                resp = app_or_url.post_json("/signin", data, headers=headers)
                resp_cookies = resp.cookies
        else:
            resp = requests.post("{}/signin".format(app_or_url), json=data, headers=headers)
            resp_cookies = resp.cookies

        # response OK (200) if directly from API /signin
        # response Found (302) if redirected UI /login
        if resp.status_code < 400:
            return resp.headers, resp_cookies

    if auth is True:
        if LooseVersion(version) >= LooseVersion("0.6.3"):
            logged_user = body.get("user", {}).get("user_name", "")
        else:
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


def check_raises(func, exception_type):
    # type: (Callable[[], None], Type[Exception]) -> Exception
    """
    Calls the callable and verifies that the specific exception was raised.

    :raise AssertionError: on failing exception check or missing raised exception.
    :returns: raised exception of expected type if it was raised.
    """
    try:
        func()
    except Exception as exc:  # pylint: disable=W0703
        assert isinstance(exc, exception_type)
        return exc
    raise AssertionError("Exception [{!s}] was not raised.".format(exception_type))


def check_no_raise(func):
    # type: (Callable[[], None]) -> None
    """
    Calls the callable and verifies that no exception was raised.

    :raise AssertionError: on any raised exception.
    """
    try:
        func()
    except Exception as exc:  # pylint: disable=W0703
        raise AssertionError("Exception [{!r}] was raised when none is expected.".format(exc))


def check_response_basic_info(response, expected_code=200, expected_type=CONTENT_TYPE_JSON, expected_method="GET"):
    # type: (AnyResponseType, int, Str, Str) -> Union[JSON, Str]
    """
    Validates basic `Magpie` API response metadata. For UI pages, employ :func:`check_ui_response_basic_info` instead.

    If the expected content-type is JSON, further validations are accomplished with specific metadata fields that are
    always expected in the response body. Otherwise, minimal validation of basic fields that can be validated regardless
    of content-type is done.

    :param response: response to validate.
    :param expected_code: status code to validate from the response.
    :param expected_type: Content-Type to validate from the response.
    :param expected_method: method 'GET', 'POST', etc. to validate from the response if an error.
    :return: json body of the response for convenience.
    """
    check_val_is_in("Content-Type", dict(response.headers), msg="Response doesn't define 'Content-Type' header.")
    content_types = get_response_content_types_list(response)
    check_val_equal(response.status_code, expected_code, msg="Response doesn't match expected HTTP status code.")
    check_val_is_in(expected_type, content_types, msg="Response doesn't match expected HTTP Content-Type header.")

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
        # error details available for any content-type, just in different format
        check_val_is_in("request_url", body)
        check_val_is_in("route_name", body)
        check_val_is_in("method", body)
        if expected_type == CONTENT_TYPE_JSON:
            check_val_equal(body["method"], expected_method)

    return body


def check_ui_response_basic_info(response, expected_code=200, expected_type=CONTENT_TYPE_HTML,
                                 expected_title="Magpie Administration"):
    # type: (AnyResponseType, int, Str, Str) -> Optional[NoReturn]
    """
    Validates minimal expected elements in a `Magpie` UI page.

    Number of validations is limited compared to API checks accomplished by :func:`check_response_basic_info`.
    That function should therefore be employed for responses coming directly from the API routes.

    :raises AssertionError: if any of the expected validation elements does not meet requirement.
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

    All methods take as input an instance of a Test Suite derived from :class:`Base_Magpie_TestCase`.
    Using this Test Suite, common arguments such as JSON headers and user session cookies are automatically extracted
    and passed down to the relevant requests.

    The multiple parameters prefixed by ``test_`` are also automatically extracted from the referenced Test Suite.
    For example, ``test_user_name`` will be retrieved from the Test Suite class when this information is required for
    the corresponding test operation. It is possible to override this behaviour with corresponding arguments prefixed
    by ``override_`` keyword. For example, if ``override_user_name`` is provided, it will be used instead of
    ``test_user_name`` from the Test Suite class. Furthermore, ``override_data`` can be provided where applicable to
    provide additional JSON payload fields in the executed request.
    """
    # pylint: disable=C0103,invalid-name

    @staticmethod
    def get_Version(test_case):
        # type: (AnyMagpieTestCaseType) -> Str
        """
        Obtains the `Magpie` version of the test instance (local or remote). This version can then be used in
        combination with :class:`LooseVersion` comparisons or :func:`warn_version` to toggle test execution of certain
        test cases that have version-dependant format, conditions or feature changes.

        This is useful *mostly* for remote server tests which could be out-of-sync compared to the current source code.
        It provides some form of backward compatibility with older instances provided that tests are updated accordingly
        when new features or changes are applied, which adds modifications to previously existing test methodologies or
        results.

        .. seealso::
            - :func:`warn_version`.

        :raises AssertionError: if the response cannot successfully retrieve the test instance version.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, "GET", "/version",
                            headers=test_case.json_headers,
                            cookies=test_case.cookies)
        json_body = check_response_basic_info(resp, 200)
        return json_body["version"]

    @staticmethod
    def check_UpStatus(test_case, method, path, override_headers=None, override_cookies=None, **request_kwargs):
        # type: (TestAppOrUrlType, Str, Str, Optional[HeadersType], Optional[CookiesType], Any) -> AnyResponseType
        """
        Verifies that the Magpie UI page at very least returned an HTTP Ok response with the displayed title.
        Validates that at the bare minimum, no underlying internal error occurred from the API or UI calls.

        :returns: response from the rendered page for further tests
        """
        cookies = override_cookies or getattr(test_case, "test_cookies", getattr(test_case, "cookies", None))
        headers = override_headers or getattr(test_case, "test_headers", getattr(test_case, "headers", None))
        resp = test_request(test_case, method, path, headers=headers, cookies=cookies, **request_kwargs)
        kw_args = {"expected_title": getattr(test_case, "magpie_title")} if hasattr(test_case, "magpie_title") else {}
        check_ui_response_basic_info(resp, **kw_args)
        return resp

    @staticmethod
    def check_FormSubmit(test_case,                        # type: Base_Magpie_TestCase
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
                         ):                                 # type: (...) -> AnyResponseType
        """
        Simulates the submission of a UI form to evaluate the status of the resulting page. Follows any redirect if the
        submission results into a HTTP Move (3xx) response to be redirected towards another page request.

        Successive calls using form submits can be employed to simulate sequential page navigation by providing back
        the returned `response` object as input to the following page with argument :paramref:`previous_response`.

        .. code-block:: json

            svc_resp = check_FormSubmit(test, form_match="goto_add_service", path="/ui/services")
            add_resp = check_FormSubmit(test, form_match="add_service", form_data={...}, previous_response=svc_resp)

        :param test_case: Test Suite to retrieve the instance and parameters to send requests to.
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

        :returns: response from the rendered page for further tests
        :raises AssertionError: if any check along the ways results into error or unexpected state.
        """
        app_or_url = get_app_or_url(test_case)
        if not isinstance(app_or_url, TestApp):
            test_case.skipTest(reason="test form submit with remote URL not implemented")
        if isinstance(previous_response, TestResponse):
            resp = previous_response
        else:
            resp = test_request(app_or_url, method, path, cookies=test_case.cookies, timeout=timeout)
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
            test_case.fail("could not find requested form for submission")
        if form_data:
            for f_field, f_value in dict(form_data).items():
                form[f_field] = f_value
        resp = form.submit(form_submit, expect_errors=expect_errors)
        while 300 <= resp.status_code < 400 and max_redirect > 0:
            resp = resp.follow()
        check_ui_response_basic_info(resp, expected_code=expected_code, expected_type=expected_type)
        return resp

    @staticmethod
    def check_Unauthorized(test_case, method, path, content_type=CONTENT_TYPE_JSON):
        # type: (AnyMagpieTestCaseType, Str, Str, Str) -> JSON
        """
        Verifies that Magpie returned an Unauthorized response.

        Validates that at the bare minimum, no underlying internal error occurred from the API or UI calls.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, method, path, cookies=test_case.cookies, expect_errors=True)
        return check_response_basic_info(resp, expected_code=401, expected_type=content_type, expected_method=method)

    @staticmethod
    def get_AnyServiceOfTestServiceType(test_case, override_service_type=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> JSON
        """Obtains the first service from all available services that match the test service type.

        :raises AssertionError: if the response could not retrieve the test service-type or any service of such type.
        """
        app_or_url = get_app_or_url(test_case)
        svc_type = override_service_type or test_case.test_service_type
        path = "/services/types/{}".format(svc_type)
        resp = test_request(app_or_url, "GET", path, headers=test_case.json_headers, cookies=test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")
        check_val_is_in("services", json_body)
        check_val_is_in(svc_type, json_body["services"])
        check_val_not_equal(len(json_body["services"][svc_type]), 0,
                            msg="Missing any required service of type: '{}'".format(test_case.test_service_type))
        services_dict = json_body["services"][svc_type]
        return list(services_dict.values())[0]

    @staticmethod
    def create_TestServiceResource(test_case, override_data=None):
        # type: (AnyMagpieTestCaseType, Optional[JSON]) -> JSON
        """Creates the test resource nested *immediately* under the test service. Test service *must* exist beforehand.

        :raises AssertionError: if the response correspond to failure to create the test resource.
        """
        app_or_url = get_app_or_url(test_case)
        TestSetup.create_TestService(test_case)
        path = "/services/{svc}/resources".format(svc=test_case.test_service_name)
        data = {
            "resource_name": test_case.test_resource_name,
            "resource_type": test_case.test_resource_type,
        }
        if override_data:
            data.update(override_data)
        resp = test_request(app_or_url, "POST", path,
                            headers=test_case.json_headers,
                            cookies=test_case.cookies, json=data)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def get_ResourceInfo(test_case, body):
        # type: (AnyMagpieTestCaseType, JSON) -> JSON
        """
        Obtains in a backward compatible way the resource details based on resource response body and the tested
        instance version.
        """
        if LooseVersion(test_case.version) >= LooseVersion("0.6.3"):
            check_val_is_in("resource", body)
            check_val_type(body["resource"], dict)
            body = body["resource"]
        return body

    @staticmethod
    def get_ExistingTestServiceInfo(test_case, override_service_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> JSON
        """Obtains test service details.

        :raises AssertionError: if the response correspond to missing service or failure to retrieve it.
        """
        app_or_url = get_app_or_url(test_case)
        svc_name = override_service_name or test_case.test_service_name
        path = "/services/{svc}".format(svc=svc_name)
        resp = test_request(app_or_url, "GET", path,
                            headers=test_case.json_headers, cookies=test_case.cookies)
        json_body = get_json_body(resp)
        svc_getter = "service"
        if LooseVersion(test_case.version) < LooseVersion("0.9.1"):
            svc_getter = svc_name
        return json_body[svc_getter]

    @staticmethod
    def get_TestServiceDirectResources(test_case, override_service_name=None, ignore_missing_service=False):
        # type: (AnyMagpieTestCaseType, Optional[Str], bool) -> List[JSON]
        """Obtains test resources nested *immediately* under test service.

        :raises AssertionError: if the response correspond to missing service or resources.
        """
        app_or_url = get_app_or_url(test_case)
        svc_name = override_service_name or test_case.test_service_name
        path = "/services/{svc}/resources".format(svc=svc_name)
        resp = test_request(app_or_url, "GET", path,
                            headers=test_case.json_headers, cookies=test_case.cookies,
                            expect_errors=ignore_missing_service)
        if ignore_missing_service and resp.status_code == 404:
            return []
        json_body = get_json_body(resp)
        resources = json_body[svc_name]["resources"]
        return [resources[res] for res in resources]

    @staticmethod
    def check_NonExistingTestServiceResource(test_case, override_service_name=None, override_resource_name=None):
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
    def delete_TestServiceResource(test_case, override_resource_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Deletes the test service. If it does not exist, skip. Otherwise, delete it and validate.

        :raises AssertionError: if any response does not correspond to non existing service after execution.
        """
        app_or_url = get_app_or_url(test_case)
        resource_name = override_resource_name or test_case.test_resource_name
        resources = TestSetup.get_TestServiceDirectResources(test_case, ignore_missing_service=True)
        test_resource = list(filter(lambda r: r["resource_name"] == resource_name, resources))
        # delete as required, skip if non-existing
        if len(test_resource) > 0:
            resource_id = test_resource[0]["resource_id"]
            path = "/services/{svc}/resources/{res_id}".format(svc=test_case.test_service_name, res_id=resource_id)
            resp = test_request(app_or_url, "DELETE", path,
                                headers=test_case.json_headers,
                                cookies=test_case.cookies)
            check_val_equal(resp.status_code, 200)
        TestSetup.check_NonExistingTestServiceResource(test_case)

    @staticmethod
    def create_TestService(test_case, override_service_name=None, override_service_type=None):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[Str]) -> JSON
        """Creates the test service. If already exists, deletes it. Then, attempt creation.

        :raises AssertionError: if any response does not correspond to successful service creation from scratch.
        """
        app_or_url = get_app_or_url(test_case)
        svc_name = override_service_name or test_case.test_service_name
        svc_type = override_service_type or test_case.test_service_type
        data = {
            "service_name": svc_name,
            "service_type": svc_type,
            "service_url": "http://localhost:9000/{}".format(svc_name)
        }
        resp = test_request(app_or_url, "POST", "/services", json=data,
                            headers=test_case.json_headers, cookies=test_case.cookies,
                            expect_errors=True)
        if resp.status_code == 409:
            path = "/services/{svc}".format(svc=svc_name)
            resp = test_request(app_or_url, "GET", path,
                                headers=test_case.json_headers,
                                cookies=test_case.cookies)
            body = check_response_basic_info(resp, 200, expected_method="GET")
            if LooseVersion(test_case.version) < LooseVersion("0.9.1"):
                body.update({"service": body[svc_name]})
                body.pop(svc_name)
            return body
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def check_NonExistingTestService(test_case, override_service_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Validates that the test service does not exist.

        :raises AssertionError: if the response does not correspond to missing service.
        """
        services_info = TestSetup.get_RegisteredServicesList(test_case)
        services_names = [svc["service_name"] for svc in services_info]
        service_name = override_service_name or test_case.test_service_name
        check_val_not_in(service_name, services_names)

    @staticmethod
    def delete_TestService(test_case, override_service_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Deletes the test service. If non existing, skip. Otherwise, proceed to remove it.

        :raises AssertionError: if the response does not correspond to successful validation or removal of the service.
        """
        app_or_url = get_app_or_url(test_case)
        service_name = override_service_name or test_case.test_service_name
        services_info = TestSetup.get_RegisteredServicesList(test_case)
        test_service = list(filter(lambda r: r["service_name"] == service_name, services_info))
        # delete as required, skip if non-existing
        if len(test_service) > 0:
            path = "/services/{svc_name}".format(svc_name=service_name)
            resp = test_request(app_or_url, "DELETE", path,
                                headers=test_case.json_headers,
                                cookies=test_case.cookies)
            check_val_equal(resp.status_code, 200)
        TestSetup.check_NonExistingTestService(test_case, override_service_name=service_name)

    @staticmethod
    def get_RegisteredServicesList(test_case):
        # type: (AnyMagpieTestCaseType) -> List[Str]
        """Obtains the list of registered users.

        :raises AssertionError: if the response does not correspond to successful retrieval of user names.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, "GET", "/services",
                            headers=test_case.json_headers,
                            cookies=test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")

        # prepare a flat list of registered services
        services_list = list()
        for svc_type in json_body["services"]:
            services_of_type = json_body["services"][svc_type]
            services_list.extend(services_of_type.values())
        return services_list

    @staticmethod
    def get_RegisteredUsersList(test_case):
        # type: (AnyMagpieTestCaseType) -> List[Str]
        """Obtains the list of registered users.

        :raises AssertionError: if the response does not correspond to successful retrieval of user names.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, "GET", "/users",
                            headers=test_case.json_headers,
                            cookies=test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")
        return json_body["user_names"]

    @staticmethod
    def check_NonExistingTestUser(test_case, override_user_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Ensures that the test user does not exist.

        :raises AssertionError: if the test user exists.
        """
        users = TestSetup.get_RegisteredUsersList(test_case)
        user_name = override_user_name or test_case.test_user_name
        check_val_not_in(user_name, users)

    @staticmethod
    def create_TestUser(test_case, override_group_name=None, override_data=None):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[JSON]) -> JSON
        """Creates the test user.

        :raises AssertionError: if the request response does not match successful creation.
        """
        app_or_url = get_app_or_url(test_case)
        data = {
            "user_name": test_case.test_user_name,
            "email": "{}@mail.com".format(test_case.test_user_name),
            "password": test_case.test_user_name,
            "group_name": override_group_name or test_case.test_group_name,
        }
        if override_data:
            data.update(override_data)
        resp = test_request(app_or_url, "POST", "/users",
                            headers=test_case.json_headers,
                            cookies=test_case.cookies, json=data)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def delete_TestUser(test_case, override_user_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Ensures that the test user does not exist. If it does, deletes him. Otherwise, skip.

        :raises AssertionError: if any request response does not match successful validation or removal from group.
        """
        app_or_url = get_app_or_url(test_case)
        users = TestSetup.get_RegisteredUsersList(test_case)
        user_name = override_user_name or test_case.test_user_name
        # delete as required, skip if non-existing
        if user_name in users:
            path = "/users/{usr}".format(usr=user_name)
            resp = test_request(app_or_url, "DELETE", path, headers=test_case.json_headers, cookies=test_case.cookies)
            check_response_basic_info(resp, 200, expected_method="DELETE")
        TestSetup.check_NonExistingTestUser(test_case, override_user_name=user_name)

    @staticmethod
    def check_UserGroupMembership(test_case,                    # type: AnyMagpieTestCaseType
                                  member=True,                  # type: bool
                                  override_user_name=None,      # type: Optional[Str]
                                  override_group_name=None,     # type: Optional[Str]
                                  override_headers=None,        # type: Optional[HeadersType]
                                  override_cookies=None,        # type: Optional[CookiesType]
                                  ):                            # type: (...) -> None
        """Ensures that the test user is a member or not of the test group (according to :paramref:`member` value).

        :raises AssertionError: if the request response does not validate of membership status of the user to the group.
        """
        app_or_url = get_app_or_url(test_case)
        usr_name = override_user_name or test_case.test_user_name
        grp_name = override_group_name or test_case.test_group_name
        cookies = override_cookies or test_case.cookies
        headers = override_headers or test_case.json_headers
        path = "/groups/{grp}/users".format(grp=grp_name)
        resp = test_request(app_or_url, "GET", path, headers=headers, cookies=cookies)
        body = check_response_basic_info(resp, 200, expected_method="GET")
        if member:
            check_val_is_in(usr_name, body["user_names"])
        else:
            check_val_not_in(usr_name, body["user_names"])

    @staticmethod
    def assign_TestUserGroup(test_case, override_user_name=None, override_group_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str], Optional[Str]) -> None
        """Ensures that the test user is a member of the test group. If already a member, skips. Otherwise, adds him.

        :raises AssertionError: if any request response does not match successful validation or assignation to group.
        """
        app_or_url = get_app_or_url(test_case)
        usr_name = override_user_name or test_case.test_user_name
        grp_name = override_group_name or test_case.test_group_name
        path = "/groups/{grp}/users".format(grp=grp_name)
        resp = test_request(app_or_url, "GET", path, headers=test_case.json_headers, cookies=test_case.cookies)
        body = check_response_basic_info(resp, 200, expected_method="GET")
        if usr_name not in body["user_names"]:
            path = "/users/{usr}/groups".format(usr=usr_name)
            data = {"group_name": grp_name}
            resp = test_request(app_or_url, "POST", path, data=data,
                                headers=test_case.json_headers, cookies=test_case.cookies)
            check_response_basic_info(resp, 201, expected_method="POST")
        TestSetup.check_UserGroupMembership(test_case, override_user_name=usr_name, override_group_name=grp_name)

    @staticmethod
    def get_RegisteredGroupsList(test_case):
        # type: (AnyMagpieTestCaseType) -> List[Str]
        """Obtains existing group names.

        :raises AssertionError: if the request response does not match successful groups retrieval.
        """
        app_or_url = get_app_or_url(test_case)
        resp = test_request(app_or_url, "GET", "/groups",
                            headers=test_case.json_headers,
                            cookies=test_case.cookies)
        json_body = check_response_basic_info(resp, 200, expected_method="GET")
        return json_body["group_names"]

    @staticmethod
    def check_NonExistingTestGroup(test_case, override_group_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Validate that test group does not exist.

        :raises AssertionError: if the test group exists
        """
        groups = TestSetup.get_RegisteredGroupsList(test_case)
        group_name = override_group_name or test_case.test_group_name
        check_val_not_in(group_name, groups)

    @staticmethod
    def create_TestGroup(test_case,                # type: Base_Magpie_TestCase
                         override_group_name=None,  # type: Optional[Str]
                         override_data=None,        # type: Optional[JSON]
                         override_headers=None,     # type: Optional[HeadersType]
                         override_cookies=None,     # type: Optional[CookiesType]
                         ):                         # type: (...) -> JSON
        """Create the test group.

        :raises AssertionError: if the request does not have expected response matching successful creation.
        """
        app_or_url = get_app_or_url(test_case)
        data = override_data or {}
        if "group_name" not in data:
            data = {"group_name": override_group_name or test_case.test_group_name}
        resp = test_request(app_or_url, "POST", "/groups",
                            headers=override_headers or test_case.json_headers,
                            cookies=override_cookies or test_case.cookies, json=data)
        return check_response_basic_info(resp, 201, expected_method="POST")

    @staticmethod
    def delete_TestGroup(test_case, override_group_name=None):
        # type: (AnyMagpieTestCaseType, Optional[Str]) -> None
        """Delete the test group.

        :raises AssertionError: if the request does not have expected response matching successful deletion.
        """
        app_or_url = get_app_or_url(test_case)
        groups = TestSetup.get_RegisteredGroupsList(test_case)
        group_name = override_group_name or test_case.test_group_name
        # delete as required, skip if non-existing
        if group_name in groups:
            path = "/groups/{grp}".format(grp=group_name)
            resp = test_request(app_or_url, "DELETE", path,
                                headers=test_case.json_headers,
                                cookies=test_case.cookies)
            check_response_basic_info(resp, 200, expected_method="DELETE")
        TestSetup.check_NonExistingTestGroup(test_case, override_group_name=group_name)
