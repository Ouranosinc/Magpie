#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_utils
----------------------------------

Tests for the various utility operations employed by Magpie.
"""
import inspect
import os
import re
import tempfile
import unittest

import mock
import six
from pyramid.httpexceptions import HTTPBadRequest, HTTPForbidden, HTTPInternalServerError, HTTPOk
from pyramid.settings import asbool

from magpie import __meta__, constants
from magpie.api import exception as ax
from magpie.api import generic as ag
from magpie.api import requests as ar
from magpie.compat import LooseVersion
from magpie.utils import CONTENT_TYPE_JSON, ExtendedEnum, get_header, get_magpie_url, import_target
from tests import runner, utils

if six.PY2:
    from backports import tempfile as tempfile2  # noqa  # pylint: disable=E0611,no-name-in-module  # Python 2
else:
    tempfile2 = tempfile  # pylint: disable=C0103,invalid-name


class DummyEnum(ExtendedEnum):
    TEST_VALUE_1 = "value-1"
    TEST_VALUE_2 = "value-2"


@runner.MAGPIE_TEST_UTILS
def test_import_target():
    func = import_target("tests/hooks/request_hooks.py:add_x_wps_output_context")
    assert func is not None
    assert inspect.isfunction(func)
    assert func.__name__ == "add_x_wps_output_context"

    here = os.path.abspath(os.path.dirname(__file__))
    _cls = import_target("test_utils.py:DummyEnum", here)
    assert _cls is not None
    assert _cls.__module__ != DummyEnum.__module__, "imported target should have its own file-based module reference"
    assert _cls is not DummyEnum, "since different module references, should be considered different references"
    assert _cls.TEST_VALUE_1.value == DummyEnum.TEST_VALUE_1.value

    root = os.path.abspath(os.path.join(here, ".."))
    with mock.patch("magpie.utils.get_constant", return_value=root):
        func = import_target("tests/hooks/request_hooks.py:add_x_wps_output_context")
        assert func is not None
        assert inspect.isfunction(func)
        assert func.__name__ == "add_x_wps_output_context"
        # if invalid default root dir does not exist, it should also fail (must not suddenly find relative path)
        rand_dir = os.path.join(root, "random")
        func = import_target("tests/hooks/request_hooks.py:add_x_wps_output_context", rand_dir)
        assert func is None

    # validate variable was employed, and not just that path happened to match
    with tempfile2.TemporaryDirectory() as tmp_dir:
        with mock.patch("magpie.utils.get_constant", return_value=tmp_dir):
            func = import_target("tests/hooks/request_hooks.py:add_x_wps_output_context")
            assert func is None
            # even if root path is invalid, if default is provided, it is prioritized
            func = import_target("tests/hooks/request_hooks.py:add_x_wps_output_context", root)
            assert func is not None
            assert inspect.isfunction(func)
            assert func.__name__ == "add_x_wps_output_context"
            # but if this default root (dir exists) produces an invalid path, then fails to locate the hooks
            func = import_target("tests/hooks/request_hooks.py:add_x_wps_output_context", tmp_dir)
            assert func is None
            # if invalid default root dir does not exist, it should also fail (no sudden success)
            rand_dir = os.path.join(tmp_dir, "random")
            func = import_target("tests/hooks/request_hooks.py:add_x_wps_output_context", rand_dir)
            assert func is None


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_UTILS
class TestUtils(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.version = __meta__.__version__  # only local test

    def test_magpie_prefix_direct_request(self):
        base_url = "http://localhost"
        for url in ["http://localhost", "http://localhost/magpie"]:
            app = utils.get_test_magpie_app({"magpie.url": url})

            path = "/version"
            resp = utils.test_request(app, "GET", path)
            utils.check_response_basic_info(resp)
            utils.check_val_equal(resp.request.url, base_url + path,
                                  "Proxied path should have been auto-resolved [URL: {}].".format(url))

    def test_magpie_prefix_request_with_multiple_route_url(self):
        """
        Test multiple request routing with fixed "MAGPIE_URL" within the API application.

        Signin with invalid credentials will call "/signin" followed by sub-request "/signin_internal" and finally
        "ZigguratSignInBadAuth". Both "/signin" and "ZigguratSignInBadAuth" use "get_multiformat_body".
        """
        from magpie.api.requests import get_value_multiformat_body_checked as real_multiform_post_checked
        base_url = "http://localhost"

        def mock_get_post(real_func, *args, **kwargs):
            if args[1] != "password":
                return real_func(*args, **kwargs)
            request, args = args[0], args[1:]
            utils.check_val_equal(request.url, base_url + _paths.pop(0),
                                  "Proxied path should have been auto-resolved [URL: {}].".format(url))
            return real_func(request, *args, **kwargs)

        for url in ["http://localhost", "http://localhost/magpie"]:
            # paths are reduced (pop in mock) each time a post to get the 'password' is called in 'login' module
            # this combination should happen twice, one in signin route and another on the redirected internal login
            _paths = ["/signin", "/signin_internal"]
            app = utils.get_test_magpie_app({"magpie.url": url})

            with mock.patch("magpie.api.requests.get_value_multiformat_body_checked",
                            side_effect=lambda *_, **__: mock_get_post(real_multiform_post_checked, *_, **__)):
                data = {"user_name": "foo", "password": "bar"}
                headers = {"Content-Type": CONTENT_TYPE_JSON, "Accept": CONTENT_TYPE_JSON}
                resp = utils.test_request(app, "POST", _paths[0], json=data, headers=headers, expect_errors=True)
                if LooseVersion(self.version) < LooseVersion("0.10.0"):
                    # user name doesn't exist
                    utils.check_response_basic_info(resp, expected_code=406, expected_method="POST")
                else:
                    # invalid username/password credentials
                    utils.check_response_basic_info(resp, expected_code=401, expected_method="POST")

    def test_get_header_split(self):
        headers = {"Content-Type": "{}; charset=UTF-8".format(CONTENT_TYPE_JSON)}
        for name in ["content_type", "content-type", "Content_Type", "Content-Type", "CONTENT_TYPE", "CONTENT-TYPE"]:
            for split in [";,", ",;", ";", (",", ";"), [";", ","]]:
                utils.check_val_equal(get_header(name, headers, split=split), CONTENT_TYPE_JSON)

    def test_get_query_param(self):
        resp = utils.mock_request("/some/path")
        v = ar.get_query_param(resp, "value")
        utils.check_val_equal(v, None)

        resp = utils.mock_request("/some/path?other=test")
        v = ar.get_query_param(resp, "value")
        utils.check_val_equal(v, None)

        resp = utils.mock_request("/some/path?other=test")
        v = ar.get_query_param(resp, "value", True)
        utils.check_val_equal(v, True)

        resp = utils.mock_request("/some/path?value=test")
        v = ar.get_query_param(resp, "value", True)
        utils.check_val_equal(v, "test")

        resp = utils.mock_request("/some/path?query=value")
        v = ar.get_query_param(resp, "query")
        utils.check_val_equal(v, "value")

        resp = utils.mock_request("/some/path?QUERY=VALUE")
        v = ar.get_query_param(resp, "query")
        utils.check_val_equal(v, "VALUE")

        resp = utils.mock_request("/some/path?QUERY=VALUE")
        v = asbool(ar.get_query_param(resp, "query"))
        utils.check_val_equal(v, False)

        resp = utils.mock_request("/some/path?Query=TRUE")
        v = asbool(ar.get_query_param(resp, "query"))
        utils.check_val_equal(v, True)

    def test_verify_param_proper_verifications_raised(self):
        # with default error
        utils.check_raises(lambda: ax.verify_param("b", param_compare=["a", "b"], not_in=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("x", param_compare=["a", "b"], is_in=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=int, is_type=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(1.0, param_compare=six.string_types, is_type=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("x", param_compare="x", not_equal=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("x", param_compare="y", is_equal=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(False, is_true=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(True, is_false=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(None, not_none=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(1, is_none=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("", not_empty=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("abc", is_empty=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("abc", matches=True, param_compare=r"[0-9]+"), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("abc", matches=True, param_compare=re.compile(r"[0-9]+")),
                           HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("abc", not_matches=True, param_compare=r"[a-z]+"),
                           HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("abc", not_matches=True, param_compare=re.compile(r"[a-z]+")),
                           HTTPBadRequest)

        # with requested error
        utils.check_raises(lambda:
                           ax.verify_param("b", param_compare=["a", "b"], not_in=True, http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param("x", param_compare=["a", "b"], is_in=True, http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=int, is_type=True, http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param("x", param_compare="x", not_equal=True, http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param("x", param_compare="y", is_equal=True, http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param(False, is_true=True, http_error=HTTPForbidden), HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param(True, is_false=True, http_error=HTTPForbidden), HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param(None, not_none=True, http_error=HTTPForbidden), HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param(1, is_none=True, http_error=HTTPForbidden), HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param("", not_empty=True, http_error=HTTPForbidden), HTTPForbidden)
        utils.check_raises(lambda: ax.verify_param("abc", is_empty=True, http_error=HTTPForbidden), HTTPForbidden)
        utils.check_raises(lambda:
                           ax.verify_param("abc", matches=True, param_compare=r"[0-9]+", http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda:
                           ax.verify_param("abc", matches=True,
                                           param_compare=re.compile(r"[0-9]+"),
                                           http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda:
                           ax.verify_param("abc", not_matches=True,
                                           param_compare=r"[a-z]+",
                                           http_error=HTTPForbidden),
                           HTTPForbidden)
        utils.check_raises(lambda:
                           ax.verify_param("abc", not_matches=True,
                                           param_compare=re.compile(r"[a-z]+"),
                                           http_error=HTTPForbidden),
                           HTTPForbidden)

    def test_verify_param_proper_verifications_passed(self):
        ax.verify_param("x", param_compare=["a", "b"], not_in=True)
        ax.verify_param("b", param_compare=["a", "b"], is_in=True)
        ax.verify_param(1, param_compare=int, is_type=True)
        ax.verify_param("x", param_compare=six.string_types, is_type=True)
        ax.verify_param("x", param_compare=str, is_type=True)
        ax.verify_param("x", param_compare="y", not_equal=True)
        ax.verify_param("x", param_compare="x", is_equal=True)
        ax.verify_param(True, is_true=True)
        ax.verify_param(False, is_false=True)
        ax.verify_param(1, not_none=True)
        ax.verify_param(None, is_none=True)
        ax.verify_param("abc", not_empty=True)
        ax.verify_param("", is_empty=True)
        ax.verify_param("abc", matches=True, param_compare=r"[a-z]+")
        ax.verify_param("abc", matches=True, param_compare=re.compile(r"[a-z]+"))
        ax.verify_param("abc", not_matches=True, param_compare=r"[0-9]+")
        ax.verify_param("abc", not_matches=True, param_compare=re.compile(r"[0-9]+"))

    def test_verify_param_args_incorrect_usage(self):
        """
        Invalid usage of function raises internal server error instead of 'normal HTTP error'.
        """
        utils.check_raises(lambda: ax.verify_param("b", param_compare=["a", "b"]),
                           HTTPInternalServerError, msg="missing any flag specification should be caught")
        utils.check_raises(lambda: ax.verify_param("b", param_compare=["a", "b"], not_in=None),  # noqa
                           HTTPInternalServerError, msg="flag specified with incorrect type should be caught")
        utils.check_raises(lambda: ax.verify_param("b", not_in=True),
                           HTTPInternalServerError, msg="missing 'param_compare' for flag needing it should be caught")
        utils.check_raises(lambda: ax.verify_param("b", param_compare=["b"], not_in=True, http_error=HTTPOk),  # noqa
                           HTTPInternalServerError, msg="incorrect HTTP class to raise error should be caught")
        utils.check_raises(lambda: ax.verify_param([1], param_compare=1, is_in=True),
                           HTTPInternalServerError, msg="incorrect non-iterable compare should raise invalid type")
        utils.check_raises(lambda: ax.verify_param("a", matches=True, param_compare=1),
                           HTTPInternalServerError, msg="incorrect matching pattern not a string or compiled pattern")
        utils.check_raises(lambda: ax.verify_param("a", not_matches=True, param_compare=1),
                           HTTPInternalServerError, msg="incorrect matching pattern not a string or compiled pattern")
        for flag in ["not_none", "not_empty", "not_in", "not_equal", "is_none", "is_empty", "is_in", "is_equal",
                     "is_true", "is_false", "is_type", "matches", "not_matches"]:
            utils.check_raises(lambda: ax.verify_param("x", **{flag: 1}),
                               HTTPInternalServerError, msg="invalid flag '{}' type should be caught".format(flag))

    def test_verify_param_compare_types(self):
        """
        Arguments ``param`` and ``param_compare`` must be of same type for valid comparison, except for ``is_type``
        where compare parameter must be the type directly.

        .. versionchanged:: 2.0

            Since ``param`` can come from user input, we should **NOT** raise ``HTTPInternalServerError`` because the
            whole point of the method is to ensure that values are compared accordingly in a controlled fashion.
            Therefore, error to be raised is an 'expected' validation failure (``HTTPBadRequest`` or whichever
            ``http_error`` provided) instead of runtime 'unexpected' processing error.

            On the other hand, when ``is_type`` flag is requested, we know that ``param_compare`` must be a type.
            Inversely, ``param_compare`` must not be a type if ``is_type`` is not requested, but other flags require
            some form of comparison between values. We evaluate these use cases here.

        .. seealso::
            - :func:`test_verify_param_args_incorrect_usage` for invalid input use-cases
        """
        # compare flags expecting a value (can only consider it bad request because comparison values are valid)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=1, is_equal=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=True, is_equal=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(1, param_compare="1", is_equal=True), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(1, param_compare=True, is_equal=True), HTTPBadRequest)
        # when compare flags expect a value but type is provided, should still detect incorrect input
        utils.check_raises(lambda: ax.verify_param(1, param_compare=int, is_equal=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=str, is_equal=True), HTTPInternalServerError)

        # compare flags expecting param_compare to be a type while value provided is not
        utils.check_raises(lambda: ax.verify_param(1, param_compare="x", is_type=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param(1, param_compare=True, is_type=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=None, is_type=True), HTTPInternalServerError)

        # compare flags expecting param_compare to be some container instance while value provided is not
        utils.check_raises(lambda: ax.verify_param(1, param_compare=1, is_in=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param(1, param_compare=list, is_in=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=str, is_in=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param(1, param_compare=1, not_in=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param(1, param_compare=list, not_in=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param("1", param_compare=str, not_in=True), HTTPInternalServerError)

        # strings cases handled correctly (no raise)
        utils.check_no_raise(lambda: ax.verify_param("1", param_compare="1", is_equal=True))

    def test_apply_param_content_pattern_param_compare_as_string(self):
        result = ax.apply_param_content({}, "value", param_name="test", param_compare=re.compile("regex"),
                                        param_content={}, with_param=True,
                                        needs_compare=True, needs_iterable=False, is_type=False,
                                        fail_conditions={"matches": False})
        assert result == {
            "param": {
                "name": "test",
                "value": "value",
                "compare": "regex",
                "conditions": {"matches": False},
            }
        }

    def test_enum_values_listing(self):
        utils.check_all_equal(DummyEnum.values(), ["value-1", "value-2"], any_order=True)

    def test_enum_get_by_value(self):
        utils.check_val_equal(DummyEnum.get("value-1"), DummyEnum.TEST_VALUE_1)
        utils.check_val_equal(DummyEnum.get("TEST_VALUE_1"), DummyEnum.TEST_VALUE_1)
        utils.check_val_equal(DummyEnum.get("random"), None)
        utils.check_val_equal(DummyEnum.get("random", "something"), "something")

    def test_enum_other(self):
        class OtherEnum(ExtendedEnum):
            TEST_VALUE_1 = DummyEnum.TEST_VALUE_1.value  # copy internal string representation

        utils.check_val_not_equal(DummyEnum.TEST_VALUE_1, OtherEnum.TEST_VALUE_1,
                                  msg="concrete enum elements should be different")

    def test_enum_titles(self):
        utils.check_val_equal(DummyEnum.TEST_VALUE_1.title, "TestValue1")
        utils.check_val_equal(DummyEnum.TEST_VALUE_2.title, "TestValue2")
        utils.check_val_equal(DummyEnum.titles(), ["TestValue1", "TestValue2"])

    def test_evaluate_call_callable_incorrect_usage(self):
        """
        Verifies that incorrect usage of utility is raised accordingly.
        """
        utils.check_raises(lambda: ax.evaluate_call(int),
                           HTTPInternalServerError, msg="invalid callable non-lambda 'call' should raise")
        utils.check_raises(lambda: ax.evaluate_call(lambda: int, fallback=int),  # noqa
                           HTTPInternalServerError, msg="invalid callable non-lambda 'fallback' should raise")

    def test_evaluate_call_recursive_safeguard(self):
        """
        Validate use case if internal function that handles formatting and generation of a resulting HTTP response
        raises itself an error (because of implementation issue), while it is processing another pre-raised error, that
        it does not end up into an endless recursive call stack of raised errors.
        """
        mock_calls = {"counter": 0}

        def mock_raise(*_, **__):
            # avoid raising forever if the real safeguard fails doing its job
            if mock_calls["counter"] >= 2 * ax.RAISE_RECURSIVE_SAFEGUARD_MAX:
                return TypeError()
            mock_calls["counter"] += 1
            raise TypeError()

        def mock_lambda_call(*_, **__):
            ax.evaluate_call(lambda: int("x"))

        try:
            app = utils.get_test_magpie_app()
            with mock.patch("magpie.api.exception.generate_response_http_format", side_effect=mock_raise):
                with mock.patch("magpie.api.login.login.get_session_view", side_effect=mock_lambda_call):
                    # Call request that ends up calling the response formatter via 'evaluate_call' itself raising to
                    # trigger 'mock_raise' recursively within 'raise_http' function.
                    # Since tweens are set up to format all response prior to return, the raised error will itself
                    # call 'raise_http' again each time operation fails, creating recursive raises.
                    # If recursive safeguard does its job, it should end up raising 'HTTPInternalServerError' directly
                    # (without further formatting attempt when reaching the MAX value), stopping the endless loop.
                    utils.test_request(app, "GET", "/session", expect_errors=True)
        except AssertionError:
            # Request called with above 'test_request' should catch the final 'HTTPInternalServerError' that is
            # raised directly instead of usual TestResponse returned. That error is again re-raised as 'AssertionError'
            pass
        except Exception as exc:
            self.fail("unexpected error during request creation should not raise: {}".format(exc))

        # if our counter reached higher than the MAX (i.e.: 2*MAX from mock), the safeguard did not do its job
        # if it did not get called at least more than once, use cases did not really get tested
        utils.check_val_is_in(mock_calls["counter"], list(range(2, ax.RAISE_RECURSIVE_SAFEGUARD_MAX + 1)))  # noqa

    def test_format_content_json_str_invalid_usage(self):
        non_json_serializable_content = {"key": HTTPInternalServerError()}
        utils.check_raises(
            lambda: ax.format_content_json_str(200, "", non_json_serializable_content, CONTENT_TYPE_JSON),
            HTTPInternalServerError, msg="invalid content format expected as JSON serializable should raise"
        )

    def test_generate_response_http_format_invalid_usage(self):
        utils.check_raises(
            lambda: ax.generate_response_http_format(None, {}, {}, "", {}),  # noqa
            HTTPInternalServerError, msg="invalid arguments resulting in error during response generation should raise"
        )

    def test_guess_target_format_default(self):
        request = utils.mock_request()
        content_type, where = ag.guess_target_format(request)
        utils.check_val_equal(content_type, CONTENT_TYPE_JSON)
        utils.check_val_equal(where, True)

    def test_get_magpie_url_defined_or_defaults(self):
        # Disable constants globals() for every case, since it can pre-loaded from .env when running all tests.
        # Always need to provide a settings container (even empty direct when nothing define in settings),
        # otherwise 'get_constant' can find the current thread settings generated by any test app
        with mock.patch.object(constants, "MAGPIE_URL", None):

            with mock.patch.dict(os.environ, {"MAGPIE_URL": ""}):
                url = utils.check_no_raise(lambda: get_magpie_url({}))
                utils.check_val_equal(url, "http://localhost:2001")

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.url": "https://test-server.com"}))
                utils.check_val_equal(url, "https://test-server.com")

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.host": "localhost"}))
                utils.check_val_equal(url, "http://localhost:2001")

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.host": "test-server.com"}))
                utils.check_val_equal(url, "http://test-server.com:2001")

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.host": "test.com", "magpie.port": "1234"}))
                utils.check_val_equal(url, "http://test.com:1234")

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.port": "1234"}))
                utils.check_val_equal(url, "http://localhost:1234")

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.port": "9000", "magpie.scheme": "https"}))
                utils.check_val_equal(url, "https://localhost:9000")

            with mock.patch.dict(os.environ, {"MAGPIE_URL": "localhost:9871"}):
                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.url": "https://test-server.com"}))
                utils.check_val_equal(url, "https://test-server.com")  # settings priority over envs

                url = utils.check_no_raise(lambda: get_magpie_url({}))
                utils.check_val_equal(url, "http://localhost:9871")  # env URL found if not in settings

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.host": "server"}))  # ignored, URL priority
                utils.check_val_equal(url, "http://localhost:9871")  # URL fixed with missing scheme even if defined

            with mock.patch.dict(os.environ, {"MAGPIE_URL": "", "MAGPIE_PORT": "1234"}):
                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.url": "https://test-server.com"}))
                utils.check_val_equal(url, "https://test-server.com")  # ignore port, URL has priority

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.host": "server"}))
                utils.check_val_equal(url, "http://server:1234")

                url = utils.check_no_raise(lambda: get_magpie_url({"magpie.scheme": "https"}))
                utils.check_val_equal(url, "https://localhost:1234")
