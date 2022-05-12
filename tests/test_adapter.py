import json
import random
import time
import unittest
import uuid
from copy import deepcopy
from typing import TYPE_CHECKING

import mock
import pytest
import six
from pyramid.httpexceptions import HTTPNotFound
from requests.structures import CaseInsensitiveDict
from six.moves.urllib.parse import urlparse

from magpie import __meta__
from magpie.constants import get_constant
from magpie.models import Route
from magpie.permissions import Access, Permission, PermissionSet, Scope
from magpie.services import ServiceAPI, ServiceInterface, ServiceWPS, invalidate_service
from magpie.utils import CONTENT_TYPE_JSON, get_magpie_url, get_twitcher_protected_service_url
from tests import interfaces as ti
from tests import runner, utils

if six.PY3:
    from magpie.adapter.magpieowssecurity import MagpieOWSSecurity, OWSAccessForbidden  # noqa: F401

if TYPE_CHECKING:
    from typing import Any, Callable, Tuple

    from mock import MagicMock

    from magpie.typedefs import AnyRequestType, AnyResponseType, CookiesType


@unittest.skipIf(six.PY2, "Unsupported Twitcher for MagpieAdapter in Python 2")
@pytest.mark.skipif(six.PY2, reason="Unsupported Twitcher for MagpieAdapter in Python 2")
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_ADAPTER
@runner.MAGPIE_TEST_FUNCTIONAL
class TestAdapter(ti.SetupMagpieAdapter, ti.UserTestCase, ti.BaseTestCase):
    """
    Validation of general :class:`magpie.adapter.MagpieAdapter` operations and its underlying service/security handling.
    """

    __test__ = True

    @classmethod
    @utils.mocked_get_settings
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.app = utils.get_test_magpie_app()
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.settings = utils.get_app_or_url(cls).app.registry.settings

        # following will be wiped on setup
        cls.test_user_name = "unittest-adapter-user"
        cls.test_group_name = "unittest-adapter-group"
        cls.test_service_name = "unittest-adapter-service"
        cls.test_service_type = ServiceAPI.service_type
        cls.test_resource_name = "test"
        cls.test_resource_type = "route"

        cls.setup_adapter()
        cls.setup_admin()
        cls.login_admin()

    def setUp(self):
        ti.UserTestCase.setUp(self)
        info = utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="read")
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="write")
        info = utils.TestSetup.create_TestServiceResource(self)
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="read")
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="write")
        self.login_test_user()

    @utils.mocked_get_settings
    def test_unauthenticated_service_blocked(self):
        """
        Validate missing authentication token blocks access to the service if not publicly accessible.
        """
        utils.check_or_try_logout_user(self)
        self.test_headers = None
        self.test_cookies = None

        path = "/ows/proxy/{}".format(self.test_service_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [POST, {}]".format(path))

    @utils.mocked_get_settings
    def test_unauthenticated_resource_allowed(self):
        """
        Validate granted access to a resource specified as publicly accessible even without any authentication token.
        """
        utils.check_or_try_logout_user(self)
        self.test_headers = None
        self.test_cookies = None

        path = "/ows/proxy/{}/{}".format(self.test_service_name, self.test_resource_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [POST, {}]".format(path))

    @utils.mocked_get_settings
    def test_unknown_service(self):
        """
        Validate that unknown service-name is handled correctly.
        """
        self.login_test_user()

        # validate it works correctly for known service
        path = "/ows/proxy/{}".format(self.test_service_name)
        req = self.mock_request(path, method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [GET, {}]".format(path))

        # when service is unknown, Magpie cannot resolve it and directly raises not found
        path = "/ows/proxy/unittest-unknown-service"
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), HTTPNotFound, msg="Using [GET, {}]".format(path))

    @utils.mocked_get_settings
    def test_unknown_resource_under_service(self):
        """
        Evaluate use-case where requested resource when parsing the request corresponds to non-existing element.

        If the targeted resource does not exist in database, `Magpie` should still allow access if its closest
        available parent permission results into Allow/Recursive.

        If the closest parent permission permission is either Match-scoped or explicit Deny, access should be refused.
        """
        self.login_test_user()

        # validate it works correctly for known Magpie resource
        path = "/ows/proxy/{}/{}".format(self.test_service_name, self.test_resource_name)
        req = self.mock_request(path, method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [GET, {}]".format(path))

        # resource is unknown, but user permission grants access to whatever 'resource' is supposedly located there
        # up to underlying service to return whichever status is appropriate, but request is forwarded as considered
        # resolved for Magpie/Twitcher roles
        path = "/ows/proxy/{}/{}".format(self.test_service_name, "unittest-unknown-resource")
        req = self.mock_request(path, method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [GET, {}]".format(path))

    @utils.mocked_get_settings
    def test_user_verify(self):
        self.login_admin()
        test_other = "unittest-adapter-other-user"
        utils.TestSetup.delete_TestUser(self, override_user_name=test_other)
        utils.TestSetup.create_TestUser(self, override_user_name=test_other, override_password=test_other)
        utils.check_or_try_logout_user(self)
        other_headers, other_cookies = utils.check_or_try_login_user(self, username=test_other, password=test_other)
        utils.check_or_try_logout_user(self)
        self.login_test_user()

        def mock_magpie_request(*args, **kwargs):
            # type: (Any, Any) -> AnyResponseType
            if args:
                method, url, args = args[0], args[1], args[2:]
            else:
                method = kwargs.pop("method")
                url = kwargs.pop("url")
            path = urlparse(url).path
            return utils.test_request(self.app, method, path, *args, **kwargs, expect_errors=True)

        # use the function that is called within the adapter to preemptively mock
        # the request 'environ' and 'cookies' properties, so that they can be found
        # by following 'pyramid.authentication.AuthTktCookieHelper' making use of them
        def mock_cookies(request):
            # type: (AnyRequestType) -> CookiesType
            from magpie.utils import get_cookies

            cookies = get_cookies(request)
            setattr(request, "environ", {})
            setattr(request, "cookies", cookies)
            return cookies

        # simulate unreachable magpie (request not yet mocked toward TestApp)
        data = {"user_name": self.test_user_name, "password": self.test_user_name}
        resp = utils.test_request(self.test_adapter_app, "POST", "/verify", json=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, expected_method="POST", expected_code=503)
        resp = utils.test_request(self.test_adapter_app, "GET", "/verify", params=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, expected_method="GET", expected_code=503)

        with mock.patch("requests.Session.request", side_effect=mock_magpie_request):
            with mock.patch("requests.request", side_effect=mock_magpie_request):
                with mock.patch("magpie.adapter.get_cookies", side_effect=mock_cookies):
                    # valid requests with equivalent content/methods
                    data = {"user_name": self.test_user_name, "password": self.test_user_name}
                    resp = utils.test_request(self.test_adapter_app, "POST", "/verify", json=data,
                                              headers=self.test_headers, cookies=self.test_cookies)
                    utils.check_response_basic_info(resp, expected_method="POST")
                    resp = utils.test_request(self.test_adapter_app, "GET", "/verify", params=data,
                                              headers=self.test_headers, cookies=self.test_cookies)
                    utils.check_response_basic_info(resp, expected_method="GET")

                    # invalid requests with different combinations
                    data = {}
                    resp = utils.test_request(self.test_adapter_app, "POST", "/verify", json=data, expect_errors=True,
                                              headers=self.test_headers, cookies=self.test_cookies)
                    utils.check_response_basic_info(resp, expected_method="POST", expected_code=400)
                    resp = utils.test_request(self.test_adapter_app, "GET", "/verify", params=data, expect_errors=True,
                                              headers=self.test_headers, cookies=self.test_cookies)
                    utils.check_response_basic_info(resp, expected_method="GET", expected_code=400)

                    utils.check_or_try_logout_user(self)
                    self.test_adapter_app.reset()  # clear saved logins
                    data = {"user_name": self.test_user_name, "password": self.test_user_name}
                    resp = utils.test_request(self.test_adapter_app, "POST", "/verify", json=data, expect_errors=True,
                                              headers={}, cookies={})
                    utils.check_response_basic_info(resp, expected_method="POST", expected_code=401)
                    resp = utils.test_request(self.test_adapter_app, "GET", "/verify", params=data, expect_errors=True,
                                              headers={}, cookies={})
                    utils.check_response_basic_info(resp, expected_method="GET", expected_code=401)

                    data = {"user_name": "bad-user", "password": self.test_user_name}
                    resp = utils.test_request(self.test_adapter_app, "POST", "/verify", json=data, expect_errors=True,
                                              headers=self.test_headers, cookies=self.test_cookies)
                    utils.check_response_basic_info(resp, expected_method="POST", expected_code=400)
                    resp = utils.test_request(self.test_adapter_app, "GET", "/verify", params=data, expect_errors=True,
                                              headers=self.test_headers, cookies=self.test_cookies)
                    utils.check_response_basic_info(resp, expected_method="GET", expected_code=400)

                    data = {"user_name": self.test_user_name, "password": self.test_user_name}
                    resp = utils.test_request(self.test_adapter_app, "POST", "/verify", json=data, expect_errors=True,
                                              headers=other_headers, cookies=other_cookies)
                    utils.check_response_basic_info(resp, expected_method="POST", expected_code=403)
                    resp = utils.test_request(self.test_adapter_app, "GET", "/verify", params=data, expect_errors=True,
                                              headers=other_headers, cookies=other_cookies)
                    utils.check_response_basic_info(resp, expected_method="GET", expected_code=403)


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_ADAPTER
@runner.MAGPIE_TEST_FUNCTIONAL
class TestAdapterHooks(ti.SetupTwitcher, ti.UserTestCase, ti.BaseTestCase):

    __test__ = True

    @classmethod
    @utils.mocked_get_settings
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.app = utils.get_test_magpie_app()
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")

        # following will be wiped on setup
        cls.test_user_name = "unittest-adapter-hooks-user"
        cls.test_group_name = "unittest-adapter-hooks-group"

        cls.setup_twitcher()
        cls.setup_admin()
        cls.login_admin()

    def test_request_response_hooks(self):
        """
        Validate hooks functionalities using examples defined in ``config/providers.cfg`` loaded by default.
        """
        utils.warn_version(self, "adapter hooks functionality", "3.25", skip=True)

        assert "magpie.services" in self.settings
        assert "weaver" in self.settings["magpie.services"]
        assert self.settings["magpie.services"]["weaver"]["hooks"]
        magpie_url = get_magpie_url(self.settings)
        weaver_url = self.settings["magpie.services"]["weaver"]["url"]
        weaver_proxy_url = get_twitcher_protected_service_url("weaver", self.settings)
        twitcher_proxy_path = "/ows/proxy"  # default

        def mock_requests(*args, **kwargs):
            # type: (Any, Any) -> AnyResponseType
            if args:
                _method, url, args = args[0], args[1], args[2:]
            else:
                _method = kwargs.pop("method")
                url = kwargs.pop("url")
            _method = _method.upper()
            _path = urlparse(url).path
            if url.startswith(magpie_url):
                return utils.test_request(self.app, _method, _path, *args, **kwargs, expect_errors=True)
            if url.startswith(weaver_url):
                # generate request object that is expected to be stored in the response for reference
                # - 'owsproxy_extra' normally sets the following, but due to our mocks they are missing
                #   those are required for Twitcher to perform appropriate service request proxying
                # - forward test application settings combining magpie+twitcher definitions
                #   since many request/response are mocked with direct objects, full reference to registry/settings
                #   are not auto-populated from the original application otherwise
                ows_proxy_params = {"extra_path": _path, "service_name": "weaver"}
                req_kwargs = {"matchdict": ows_proxy_params, "settings": self.settings}
                req_kwargs.update(kwargs)
                request = utils.mock_request(_path, _method, **req_kwargs)
                if _path.endswith("jobs") and _method == "POST":
                    # retrieve the header that should have been applied by the request hook
                    # forward it in the response body for testing result
                    headers = CaseInsensitiveDict(kwargs.get("headers", {}))
                    x_wps_out_context = headers.get("X-WPS-Output-Context")
                    wps_job_id = str(uuid.uuid4())
                    wps_job_url = weaver_proxy_url + "/jobs/" + wps_job_id
                    return utils.mock_response(
                        {"status": "accepted", "jobID": wps_job_id, "context": x_wps_out_context},
                        status=201, headers={"Content-Type": CONTENT_TYPE_JSON, "Location": wps_job_url},
                        request=request,
                    )
                parts = _path.rsplit("/", 2)
                if parts[-2] == "jobs" and _method == "GET":
                    return utils.mock_response(
                        {"status": "succeeded", "jobID": parts[-1]},
                        status=200, headers={"Content-Type": CONTENT_TYPE_JSON},
                        request=request
                    )
            raise ValueError("Unknown location for mock request: [{}]".format(url))

        test_user = utils.TestSetup.get_UserInfo(self, override_username=self.test_user_name)
        test_user_id = test_user["user_id"]

        # setup user to be allowed access to following operations
        self.login_admin()
        job_json = utils.TestSetup.create_TestServiceResource(
            self, "weaver", ServiceAPI.service_type, "jobs", Route.resource_type_name, ignore_conflict=True
        )
        job_info = utils.TestSetup.get_ResourceInfo(self, override_body=job_json)
        utils.TestSetup.create_TestUserResourcePermission(
            self, job_info, override_user_name=test_user["user_name"], override_exist=True,
            override_permission=PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)
        )
        utils.TestSetup.create_TestUserResourcePermission(
            self, job_info, override_user_name=test_user["user_name"], override_exist=True,
            override_permission=PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)
        )
        self.login_test_user()

        with mock.patch("requests.Session.request", side_effect=mock_requests):
            with mock.patch("requests.request", side_effect=mock_requests) as mock_req:
                with utils.wrapped_call("magpie.adapter.import_target") as import_hook_target:
                    path = twitcher_proxy_path + "/weaver/jobs"
                    resp = utils.test_request(self.test_twitcher_app, "POST", path, json={},
                                              headers=self.test_headers, cookies=self.test_cookies)
                utils.check_val_equal(import_hook_target.call_count, 1,
                                      msg="Only a single hook expected to be matched against request parameters.")
                utils.check_val_not_equal(import_hook_target.call_args_list[-1].return_value, None,
                                          msg="Imported target expected to have succeeded and found the function.")

                # check request hook called
                utils.check_val_equal(resp.status_code, 201)
                utils.check_val_is_in("context", resp.json)
                utils.check_val_equal(resp.json["context"], "user-" + str(test_user_id))
                job_url = resp.headers["Location"]
                assert job_url and twitcher_proxy_path in job_url and "weaver/jobs" in job_url
                utils.check_val_equal(mock_req.call_count, 1)
                mock_kwargs = mock_req.call_args_list[0].kwargs
                expect_data = json.dumps({"hooks": 5, "hook": "add_x_wps_output_context"}).encode("utf-8")
                utils.check_val_is_in("data", mock_kwargs)
                utils.check_val_equal(mock_kwargs["data"], expect_data)

                with utils.wrapped_call("magpie.adapter.import_target") as import_hook_target:
                    path = twitcher_proxy_path + job_url.rsplit(twitcher_proxy_path, 1)[-1]
                    resp = utils.test_request(self.test_twitcher_app, "GET", path,
                                              headers=self.test_headers, cookies=self.test_cookies)
                utils.check_val_equal(import_hook_target.call_count, 2,
                                      msg="Two hooks expected to be matched against request parameters.")
                utils.check_val_not_equal(import_hook_target.call_args_list[-1].return_value, None,
                                          msg="Imported target expected to have succeeded and found the function.")
                # check response hook called
                utils.check_val_equal(resp.status_code, 200)
                utils.check_val_equal(mock_req.call_count, 2)  # previous + current request
                utils.check_val_is_in("X-WPS-Output-Location", resp.headers)
                utils.check_val_is_in("X-WPS-Output-Context", resp.headers)
                utils.check_val_is_in("X-WPS-Output-Link", resp.headers)
                utils.check_val_is_in("X-Magpie-Hook-Name", resp.headers)
                utils.check_val_is_in("X-Magpie-Hook-Index", resp.headers)
                utils.check_val_is_in("X-Magpie-Hook-Target", resp.headers)
                utils.check_val_equal(resp.headers["X-WPS-Output-Context"], "user-" + str(test_user_id))
                utils.check_val_equal(resp.headers["X-Magpie-Hook-Name"], "add_x_wps_output_link")
                test_hook = self.settings["magpie.services"]["weaver"]["hooks"][3]
                utils.check_val_equal(resp.headers["X-Magpie-Hook-Target"], test_hook["target"])
                utils.check_val_equal(resp.headers["X-Magpie-Hook-Index"], "4")  # string because header requires it


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_ADAPTER
@runner.MAGPIE_TEST_CACHING
@runner.MAGPIE_TEST_FUNCTIONAL
class BaseTestAdapterCaching(ti.SetupMagpieAdapter, ti.UserTestCase, ti.BaseTestCase):
    """
    Base methods for testing requests parsing and :term:`ACL` resolution when caching is enabled.

    .. warning::
        Caching tests are time-dependant.
        While debugging, exceeding the value of :data:`cache_expire` could make a test fail because cache was reset.
        This is the case especially for requests count comparisons.

    .. seealso::
        - :class:`TestAdapterCachingAllRegions`
        - :class:`TestAdapterCachingPartialRegions`
    """
    # pylint: disable=C0103,invalid-name
    __test__ = False
    test_headers = None
    test_cookies = None
    cache_expire = None
    cache_enabled = False
    cache_settings = None  # if defined, overrides other 'cache_<>' parameters above (explicit 'beaker' configuration)
    cache_reset_headers = {"Cache-Control": "no-cache"}  # requests with this header reset caches to force function call

    @classmethod
    def setUpClass(cls):
        cls.version = utils.TestSetup.get_Version(cls)
        cls.settings = {}
        cls.app = None
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")

        # following will be wiped on setup
        cls.test_user_name = "unittest-adapter-cache-user"
        cls.test_group_name = "unittest-adapter-cache-group"
        cls.test_service_name = "unittest-adapter-cache-service"
        cls.test_service_type = ServiceAPI.service_type
        cls.test_resource_type = "route"

    @utils.mocked_get_settings
    def setUp(self):
        self.reset_cached_app(settings=self.cache_settings)
        ti.UserTestCase.setUp(self)
        self.cookies = None
        self.headers, self.cookies = utils.check_or_try_login_user(self, self.usr, self.pwd, use_ui_form_submit=True)
        self.require = "cannot run tests without logged in user with '{}' permissions".format(self.grp)
        self.login_admin()
        utils.TestSetup.delete_TestService(self)
        utils.TestSetup.create_TestService(self)
        invalidate_service(self.test_service_name)

    @classmethod
    def reset_cached_app(cls, settings=None):
        cache_settings = deepcopy(cls.settings)
        if not settings:
            utils.setup_cache_settings(cache_settings, force=True, enabled=cls.cache_enabled, expire=cls.cache_expire)
        else:
            cache_settings.update(settings)

        cls.app = utils.get_test_magpie_app(settings=cache_settings)
        cls.setup_adapter(setup_cache=False)  # don't override adapter cache settings pre-defined above
        cls.setup_admin()

    def run_with_caching_mocks(self, service, operations):
        # type: (ServiceInterface, Callable[[], None]) -> Tuple[MagicMock, MagicMock, MagicMock, MagicMock]
        """
        Runs the operations with mocks wrapping important functions that allow counting cached vs non-cached calls.

        :param service: handle to service that will be called/cached and retrieved during requests
        :param operations: callable that should trigger the requests/caching tests (no argument, no return)
        :returns
            Tuple of mock handles to called operations:
            - service calls retrieved from cache
            - service calls generated from request
            - ACL resolution retrieved from cache
            - ACL resolution computed from request
        """
        def mocked_service_factory(__test_service, test_request):
            service.request = test_request
            return service

        # WARNING:
        #  In both cases below, we cannot mock the cached method directly since beaker needs it to do caching retrieval.
        #  Instead, mock a function before each cached method and another within cached method to compare call-counts.

        # wrap 'get_service' which calls the cached method '_get_service_cached', which in turn calls 'service_factory'
        # when caching takes effect, 'service_factory' does not get called as the cached service is returned directly
        with utils.wrapped_call(MagpieOWSSecurity, "get_service", self.ows) as mock_service_cached:
            with utils.wrapped_call("magpie.adapter.magpieowssecurity.service_factory",
                                    side_effect=mocked_service_factory) as mock_service_factory:
                # wrap '__acl__' which calls '_get_acl_cached', that in turns calls '_get_acl' when resolving real ACL
                with utils.wrapped_call(ServiceInterface, "__acl__", service) as mock_acl_cached:
                    with utils.wrapped_call(ServiceInterface, "_get_acl", service) as mock_acl_resolve:
                        operations()
        return mock_service_cached, mock_service_factory, mock_acl_cached, mock_acl_resolve


class TestAdapterCachingAllRegions(BaseTestAdapterCaching):
    __test__ = True
    test_headers = None
    test_cookies = None
    cache_expire = 600
    cache_enabled = True
    cache_reset_headers = {"Cache-Control": "no-cache"}

    @utils.mocked_get_settings
    def test_access_cached_service(self):
        """
        Verify caching operation of adapter to retrieve the requested service.

        Caching limits retrieval of service implementation from database service definition matched by service name.
        """
        number_calls = 10
        admin_headers = self.headers.copy()
        admin_cookies = self.cookies.copy()
        admin_no_cache = self.cache_reset_headers.copy()
        admin_no_cache.update(admin_headers)

        # wrap 'get_service' which calls the cached method, which in turn calls 'service_factory'
        # when caching takes effect, 'service_factory' does not get called as the cached service is returned directly
        with utils.wrapped_call(MagpieOWSSecurity, "get_service", self.ows) as mock_cached:
            with utils.wrapped_call("magpie.adapter.magpieowssecurity.service_factory") as mock_service:

                # initial request to ensure functions get cached once from scratch
                path = "/ows/proxy/{}".format(self.test_service_name)
                msg = "Using [GET, {}]".format(path)
                req = self.mock_request(path, method="GET", headers=admin_no_cache, cookies=admin_cookies)
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

                # run many requests which should directly return the previously cached result
                req = self.mock_request(path, method="GET", headers=admin_headers, cookies=admin_cookies)
                for _ in range(number_calls):
                    utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

        utils.check_val_equal(mock_service.call_count, 1, msg="Real call expected only on first run before caching")
        utils.check_val_equal(mock_cached.call_count, number_calls + 1, msg="Cached call expected for each request")

    @utils.mocked_get_settings
    def test_access_cached_service_by_other_user(self):
        """
        Verify that cached service doesn't result into invalid permission access when different user sends the request.

        Although service is cached, the resolution of the given user doing the request must still resolve correctly.
        """

        admin_headers = self.headers.copy()
        admin_cookies = self.cookies.copy()
        admin_no_cache = self.cache_reset_headers.copy()
        admin_no_cache.update(admin_headers)

        # wrap 'get_service' which calls the cached method, which in turn calls 'service_factory'
        # when caching takes effect, 'service_factory' does not get called as the cached service is returned directly
        with utils.wrapped_call(MagpieOWSSecurity, "get_service", self.ows) as wrapped_service:
            with utils.wrapped_call("magpie.adapter.magpieowssecurity.service_factory") as wrapped_cached:

                # always hit the same endpoint for each request
                path = "/ows/proxy/{}".format(self.test_service_name)
                msg = "Using [GET, {}]".format(path)

                # initial request to ensure functions get cached once from scratch
                req = self.mock_request(path, method="GET", headers=admin_no_cache, cookies=admin_cookies)
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

                # same request by admin, but with caching from previous call allowed for sanity check
                req = self.mock_request(path, method="GET", headers=self.headers, cookies=self.cookies)
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

                # finally, request for unauthorized user access to the service with cache still enabled
                self.login_test_user()
                req = self.mock_request(path, method="GET")
                msg += " Expected unauthorized user refused access, not inheriting access of previous cached request"
                utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)

        utils.check_val_equal(wrapped_cached.call_count, 1, msg="Real call expected only on first run before caching")
        utils.check_val_equal(wrapped_service.call_count, 3, msg="Service call expected for each request")

    @runner.MAGPIE_TEST_PERFORMANCE
    @utils.mocked_get_settings
    def test_retrieve_cached_acl(self):
        """
        Validate caching of :term:`ACL` resolution against repeated combinations of caching arguments.

        Caching method takes as inputs combinations of (:term:`User`, :term:`Resource`, :term:`Permission`).

        Verify that the caching takes effect, but also that it is properly managed between distinct consecutive
        requests. Multiple combinations of :term:`ACL` resolution requests are sent in random order to ensure they
        don't invalidate other caches (of other combinations), while still producing valid results for the relevant
        :term:`Resource` the :term:`User` attempts to obtain :term:`Permission` access.

        When :term:`ACL` caching is applied properly, the complete computation of the access result should only be
        accomplished on the first call of each combination, and all following ones (within the caching timeout) will
        resolve from the cache.

        Validates also correct invalidation of :term:`ACL` caches when corresponding :term:`Service` caches get reset
        using the ``Cache-Control: no-cache`` header.

        Finally, validate performance such that requests with caching provide an increased response time.
        """
        # create some test resources under the service with permission for the user
        # service not allowed access, resource allowed
        res1_name = "test1"
        res2_name = "test2"
        res1_path = "/ows/proxy/{}/{}".format(self.test_service_name, res1_name)
        res2_path = "/ows/proxy/{}/{}".format(self.test_service_name, res2_name)
        info = utils.TestSetup.create_TestServiceResource(self, override_resource_name=res1_name)
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="read")
        info = utils.TestSetup.create_TestServiceResource(self, override_resource_name=res2_name)
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="write")

        no_cache_header = self.cache_reset_headers.copy()
        admin_cookies = self.cookies.copy()
        admin_headers = self.headers.copy()
        self.login_test_user()
        user_cookies = self.test_cookies.copy()
        user_headers = self.test_headers.copy()
        utils.check_or_try_logout_user(self)
        self.test_headers = None
        self.test_cookies = None

        test_requests = [
            # allowed because admin
            (True, self.mock_request(res1_path, method="GET", headers=admin_headers, cookies=admin_cookies)),
            (True, self.mock_request(res1_path, method="POST", headers=admin_headers, cookies=admin_cookies)),
            (True, self.mock_request(res2_path, method="GET", headers=admin_headers, cookies=admin_cookies)),
            (True, self.mock_request(res2_path, method="POST", headers=admin_headers, cookies=admin_cookies)),
            # allowed/denied based on (user, resource, permission) combination
            (True, self.mock_request(res1_path, method="GET", headers=user_headers, cookies=user_cookies)),
            (False, self.mock_request(res1_path, method="POST", headers=user_headers, cookies=user_cookies)),
            (False, self.mock_request(res2_path, method="GET", headers=user_headers, cookies=user_cookies)),
            (True, self.mock_request(res2_path, method="POST", headers=user_headers, cookies=user_cookies)),
        ]
        number_duplicate_call_cached = 20
        cache_requests = test_requests * number_duplicate_call_cached
        random.shuffle(cache_requests)

        # each method targets a different Permission, each path a different Resource, and each cookies a different user
        token = get_constant("MAGPIE_COOKIE_NAME")
        unique_calls = set((req.method, req.path_qs, req.cookies[token]) for _, req in test_requests + cache_requests)

        def run_check(test_requests_set, cached):
            _cached = " (cached)" if cached else ""
            for i, (_allowed, _request) in enumerate(test_requests_set):
                _cookie = _request.cookies[token]
                _user = self.test_user_name if _cookie == user_cookies[token] else "admin"
                _msg = "Using ({}) [{}, {}]{} with user [{}]".format(
                    i, _request.method, _request.path_qs, _cached, _user
                )
                if not cached:
                    _request.headers.update(no_cache_header)
                else:
                    _request.headers.pop("Cache-Control", None)
                if _allowed:
                    utils.check_no_raise(lambda: self.ows.check_request(_request), msg=_msg)
                else:
                    utils.check_raises(lambda: self.ows.check_request(_request), OWSAccessForbidden, msg=_msg)

        # obtain a reference to the 'service' that should be returned by 'service_factory' such that we can
        # prepare wrapped mock references to its '__acl__' and '_get_acl' methods
        tmp_req = test_requests[0][1]
        service = self.ows.get_service(tmp_req)
        invalidate_service(self.test_service_name)

        def test_ops():
            # run all requests with caching disabled to initialize their expire duration
            run_check(test_requests, False)
            # then, do exactly the same but with caches enabled for requests in random order
            # all caches should remain active for the whole duration and not conflict with each other
            run_check(cache_requests, True)

        # run cached requests tests
        t_start = time.perf_counter()
        mock_service_cached, mock_service, mock_acl_cached, mock_acl = self.run_with_caching_mocks(service, test_ops)
        t_exec = time.perf_counter() - t_start

        # validate performance
        #   average execution times for 'number_duplicate_call_cached = 20' and 8 requests in 'test_requests'
        #   caching:  ~[0.15s, 0.30s]
        #   no cache: ~[1.20s, 1.50s]
        t_avg_min = 1.0  # to be safe, use >2x caching max times, that is still well below no-cache min times
        utils.check_val_true(t_exec < t_avg_min, msg="Average execution time should be much lower with caching active")

        # there should be as many service resolution as there are requests, but only first ones without cache fetches it
        # for ACL resolution, there should also be as many as there are requests, but actual computation will be limited
        # to the number of combinations without caching, and all others only return the precomputed cache result
        total_cached = len(cache_requests)
        total_no_cache = len(test_requests)
        total_calls = total_cached + total_no_cache
        # Because each request in 'test_requests' that targets the same 'service' with 'no-cache' header resets it,
        # and because each 'service' cache reset also invalidates *all* ACL caches that refer to that 'service', the
        # number of real ACL resolution is repeated until caching of the last request in 'test_requests' is reached.
        # (ie: 1st request of 'test_requests' resets ACL cache due to 'no-cache', then computes ACL, and finally stores
        #      the result it in cache. Following requests to same (user/resource/permission) and without 'no-cache'
        #      header would *normally* use those cached ACL directly instead of re-computing them, but 2nd request
        #      in 'test_requests' pointing to different ACL combination re-flushes the 1st ACL cache since 'no-cache'
        #      header applies to the whole 'service' and its children ACL caches. This goes on until the last 'no-cache'
        #      request that pre-flushes cache, computes ACL, but then stores them for future requests. Being the last
        #      request resolved, those final cached ACL remains valid, while N-1 requests before must recalculate
        #      invalidated ACL once against on the first pass of non-'no-cache' header requests.)
        total_acl_cached = len(unique_calls) * 2 - 1
        utils.check_val_equal(mock_service_cached.call_count, total_calls,
                              msg="Cached service call expected for each request")
        utils.check_val_equal(mock_acl_cached.call_count, total_calls,
                              msg="Cached ACL resolution expected for each request")
        utils.check_val_equal(mock_service.call_count, total_no_cache,
                              msg="Real service call expected for each no-cache request, but not for other cached ones")
        utils.check_val_equal(mock_acl.call_count, total_acl_cached,
                              msg="Real ACL call expected only on first unique combination of cached ACL")

    @utils.mocked_get_settings
    def test_cached_service_ows_parser_request(self):
        """
        Validate that OWS parser resolves the correct request reference from previously fetched and cached service.

        Because many objects refer to the :class:`pyramid.request.Request` for different purposes, some object cached
        and others referring to that cached state, updated references must be ensured everywhere for new requests that
        could change request query parameters, headers, authentication tokens, etc.
        """

        # create some test OWS service (WPS used, but could be any)
        svc_name = self.test_service_name + "_wps"
        svc_type = ServiceWPS.service_type
        utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
        svc_info = utils.TestSetup.create_TestService(self,
                                                      override_service_name=svc_name,
                                                      override_service_type=svc_type)
        if utils.TestVersion(self.version) >= utils.TestVersion("3.22"):
            anonymous = get_constant("MAGPIE_ANONYMOUS_GROUP")
            utils.TestSetup.create_TestGroupResourcePermission(self,
                                                               resource_info=svc_info,
                                                               override_group_name=anonymous,
                                                               override_permission=Permission.GET_CAPABILITIES)
            utils.TestSetup.create_TestGroupResourcePermission(self,
                                                               resource_info=svc_info,
                                                               override_group_name=anonymous,
                                                               override_permission=Permission.EXECUTE)
        else:
            anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
            utils.TestSetup.create_TestUserResourcePermission(self,
                                                              resource_info=svc_info,
                                                              override_user_name=anonymous,
                                                              override_permission=Permission.GET_CAPABILITIES)
            utils.TestSetup.create_TestUserResourcePermission(self,
                                                              resource_info=svc_info,
                                                              override_user_name=anonymous,
                                                              override_permission=Permission.EXECUTE)

        utils.check_or_try_logout_user(self)  # anonymous
        self.test_headers = None
        self.test_cookies = None

        svc_path_getcap = "/ows/proxy/{}?request=GetCapabilities&service=WPS".format(svc_name)  # allowed
        svc_path_desc = "/ows/proxy/{}?request=DescribeProcess&service=WPS".format(svc_name)  # denied
        svc_path_exec = "/ows/proxy/{}?request=Execute&service=WPS".format(svc_name)  # denied
        test_requests = [
            # First request should trigger caching of the service as 'Allowed' and corresponding ACL resolution.
            (True, self.mock_request(svc_path_getcap, method="GET")),
            # Following requests should reuse the cached service, not triggering another 'service_factory' operation.
            # On the other hand, the distinct query parameter 'request=<>' should trigger a different ACL resolution.
            # Since they all use 'service.request' object inside cached 'service', correct update of references
            # to 'parser.request' should properly resolve as defined access.
            # Test one of each Allowed/Denied resolution, to ensure the cached 'service' did not interfere with ACL
            (False, self.mock_request(svc_path_desc, method="GET")),
            (True, self.mock_request(svc_path_exec, method="GET")),
        ]
        # Run multiple other requests afterwards to ensure that mix-and-match of above combinations still make use
        # of the cached service and cached ACL following first resolution of each case.
        number_duplicate_call_cached = 5
        cache_requests = test_requests * number_duplicate_call_cached
        random.shuffle(cache_requests)

        # each method targets a different Permission (via query param 'request=<>')
        unique_calls = set((req.method, req.path_qs) for _, req in test_requests + cache_requests)

        def run_check(test_requests_set):
            for _allowed, _request in test_requests_set:
                _msg = "Using [{}, {}] with user [{}]".format(_request.method, _request.path_qs, anonymous)
                if _allowed:
                    utils.check_no_raise(lambda: self.ows.check_request(_request), msg=_msg)
                else:
                    utils.check_raises(lambda: self.ows.check_request(_request), OWSAccessForbidden, msg=_msg)

        # obtain a reference to the 'service' that should be returned by 'service_factory' such that we can
        # prepare wrapped mock references to its '__acl__' and '_get_acl' methods
        # ensure following 'get_service' call doesn't trigger caching before running the tests with no-cache header
        tmp_req = self.mock_request(svc_path_getcap, method="GET", headers=self.cache_reset_headers)
        service = self.ows.get_service(tmp_req)
        invalidate_service(svc_name)

        def test_ops():
            run_check(test_requests)  # run all requests that triggers initial caching
            run_check(cache_requests)  # run them using caches, not triggering full ACL resolutions

        mock_service_cached, mock_service, mock_acl_cached, mock_acl = self.run_with_caching_mocks(service, test_ops)

        # There should be as many service resolution as there are requests, but only first one without cache fetches it.
        # ACL resolution should also occur once for each 'request=<>' permission.
        total_cached = len(cache_requests)
        total_no_cache = len(test_requests)
        total_calls = total_cached + total_no_cache
        total_acl_cached = len(unique_calls)
        utils.check_val_equal(mock_service_cached.call_count, total_calls,
                              msg="Cached service call expected for each request")
        utils.check_val_equal(mock_acl_cached.call_count, total_calls,
                              msg="Cached ACL resolution expected for each request")
        utils.check_val_equal(mock_service.call_count, 1,
                              msg="Real service call expected only for first call since it is always the same service")
        utils.check_val_equal(mock_acl.call_count, total_acl_cached,
                              msg="Real ACL expected only once per unique permission combination")

    @utils.mocked_get_settings
    def test_cached_service_invalidated_acl(self):
        """
        Validate that any operation triggering cached service's invalidation also invalidates corresponding ACL caches.
        """

        svc1_name = self.test_service_name + "_invalidate_1"
        svc2_name = self.test_service_name + "_invalidate_2"
        svc1_path = "/ows/proxy/{}".format(svc1_name)
        svc2_path = "/ows/proxy/{}".format(svc2_name)
        info = utils.TestSetup.create_TestService(self, override_service_name=svc1_name)
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="read")
        info = utils.TestSetup.create_TestService(self, override_service_name=svc2_name)
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission="read")

        admin_cookies = self.cookies.copy()
        self.login_test_user()
        user_cookies = self.test_cookies.copy()
        user_headers = self.test_headers.copy()
        utils.check_or_try_logout_user(self)
        self.test_headers = None
        self.test_cookies = None

        tmp_req = self.mock_request(svc1_path, method="GET", headers=self.cache_reset_headers.copy())
        svc1_ref = self.ows.get_service(tmp_req)
        tmp_req = self.mock_request(svc2_path, method="GET", headers=self.cache_reset_headers.copy())
        svc2_ref = self.ows.get_service(tmp_req)
        invalidate_service(svc1_name)
        invalidate_service(svc2_name)

        def run_svc_req(_svc_path):
            _msg = "User is expected to have access to service"
            _req = self.mock_request(_svc_path, method="GET", headers=user_headers, cookies=user_cookies)
            utils.check_no_raise(lambda: self.ows.check_request(_req), msg=_msg)
            utils.check_no_raise(lambda: self.ows.check_request(_req), msg=_msg)

        # run first set of requests to trigger caching of both Service and ACL, for both services
        for svc_path, svc_ref in [(svc1_path, svc1_ref), (svc2_path, svc2_ref)]:
            mocks = self.run_with_caching_mocks(svc_ref, lambda: run_svc_req(svc_path))
            mock_svc_cached, mock_svc_real, mock_acl_cached, mock_acl_real = mocks
            utils.check_val_equal(mock_svc_cached.call_count, 2,
                                  msg="Cached service call expected for each request (preparation)")
            utils.check_val_equal(mock_acl_cached.call_count, 2,
                                  msg="Cached ACL resolution expected for each request (preparation)")
            utils.check_val_equal(mock_svc_real.call_count, 1,
                                  msg="Real service call expected only for first request before caching (preparation)")
            utils.check_val_equal(mock_acl_real.call_count, 1,
                                  msg="Real ACL call expected only for first request before caching (preparation)")

        # trigger service cache invalidation
        # NOTE:
        #  It is important that the operation done by the method only explicitly interacts with the Service cache and
        #  not the ACL cache. Only service cache invalidation should also cascade invalidation of corresponding ACL
        #  caches for that service.

        # path not important, only need a 'request' object with 'no-cache' set
        req_no_cache = self.mock_request("", method="GET", headers=self.cache_reset_headers.copy())
        req_no_cache.registry["dbsession_factory"] = lambda *_, **__: self.session
        with mock.patch("magpie.adapter.magpieservice.get_admin_cookies", lambda *_, **__: admin_cookies):
            store = self.adapter.servicestore_factory(req_no_cache)
        store.fetch_by_name(svc1_name)  # this triggers invalidate service cache because of request no-cache header

        # re-run service/ACL requests, now cache should have been invalidated for service 1, but not for service 2
        # because service 1 caches and its corresponding ACL caches were reset, same counts as last run
        # for service 2 though, real call count should be 0 because they are still in valid caches
        mocks1 = self.run_with_caching_mocks(svc1_ref, lambda: run_svc_req(svc1_path))
        mocks2 = self.run_with_caching_mocks(svc2_ref, lambda: run_svc_req(svc2_path))
        mock_svc1_cached, mock_svc1_real, mock_acl1_cached, mock_acl1_real = mocks1
        mock_svc2_cached, mock_svc2_real, mock_acl2_cached, mock_acl2_real = mocks2
        utils.check_val_equal(mock_svc1_cached.call_count, 2,
                              msg="Cached service call expected for each request")
        utils.check_val_equal(mock_acl1_cached.call_count, 2,
                              msg="Cached ACL resolution expected for each request")
        utils.check_val_equal(mock_svc1_real.call_count, 1,
                              msg="Real service call expected only for first request before caching (after reset)")
        utils.check_val_equal(mock_acl1_real.call_count, 1,
                              msg="Real ACL call expected only for first request before caching (after reset)")
        utils.check_val_equal(mock_svc2_cached.call_count, 2,
                              msg="Cached service call expected for each request")
        utils.check_val_equal(mock_acl2_cached.call_count, 2,
                              msg="Cached ACL resolution expected for each request")
        utils.check_val_equal(mock_svc2_real.call_count, 0,
                              msg="Real service call not expected since caches should remain valid (after reset)")
        utils.check_val_equal(mock_acl2_real.call_count, 0,
                              msg="Real ACL call not expected since caches should remain valid (after reset)")


class TestAdapterCachingPartialRegions(BaseTestAdapterCaching):
    __test__ = True
    test_headers = None
    test_cookies = None
    cache_expire = None
    cache_enabled = True
    # below cache settings overrides all cache parameters above
    cache_settings = {"cache.enabled": "false", "cache.acl.enabled": "false", "cache.service.enabled": "true"}
    cache_reset_headers = {"Cache-Control": "no-cache"}

    @utils.mocked_get_settings
    def test_cached_service_uncached_acl(self):
        """
        Validate that service with cached enabled combined with ACL not cached still works as expected.

        When service is correctly retrieved from cache, but ACL employed to resolve effective permissions on that
        service are not yet cached, the database session state must be refreshed and applied to that cached service
        in other to properly resolve resource/permission hierarchy.

        .. seealso::
            :meth:`magpie.services.ServiceInterface.effective_permissions` (around start of loop)
        """
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        svc_name = self.test_service_name + "_wps-partial-cache"
        svc_type = ServiceWPS.service_type
        utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
        info = utils.TestSetup.create_TestService(self, override_service_name=svc_name, override_service_type=svc_type)

        if utils.TestVersion(self.version) >= utils.TestVersion("3.22"):
            utils.TestSetup.create_TestGroupResourcePermission(self, resource_info=info,
                                                               override_group_name=anonymous,  # same as user (forced)
                                                               override_permission=Permission.GET_CAPABILITIES)
        else:
            utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info,
                                                              override_user_name=anonymous,
                                                              override_permission=Permission.GET_CAPABILITIES)
        utils.check_or_try_logout_user(self)

        svc_path_getcap = "/ows/proxy/{}?request=GetCapabilities&service=WPS".format(svc_name)  # allowed
        svc_path_desc = "/ows/proxy/{}?request=DescribeProcess&service=WPS".format(svc_name)  # denied
        svc_path_exec = "/ows/proxy/{}?request=Execute&service=WPS".format(svc_name)  # denied
        test_requests = [
            # First request should trigger caching of the service, following use the cache
            # For each case, ACL should never be cached.
            (True, self.mock_request(svc_path_getcap, method="GET")),
            (False, self.mock_request(svc_path_desc, method="GET")),
            (False, self.mock_request(svc_path_exec, method="GET")),
        ]
        # Run multiple other requests afterwards to ensure that mix-and-match of above combinations still make use
        # of the cached service and cached ACL following first resolution of each case.
        number_duplicate_call_cached = 5
        cache_requests = test_requests * number_duplicate_call_cached
        random.shuffle(cache_requests)

        def run_check(test_requests_set):
            for _allowed, _request in test_requests_set:
                _msg = "Using [{}, {}] with user [{}]".format(_request.method, _request.path_qs, anonymous)
                if _allowed:
                    utils.check_no_raise(lambda: self.ows.check_request(_request), msg=_msg)
                else:
                    utils.check_raises(lambda: self.ows.check_request(_request), OWSAccessForbidden, msg=_msg)

        # obtain a reference to the 'service' that should be returned by 'service_factory' such that we can
        # prepare wrapped mock references to its '__acl__' and '_get_acl' methods
        # ensure following 'get_service' call doesn't trigger caching before running the tests with no-cache header
        tmp_req = self.mock_request(svc_path_getcap, method="GET", headers=self.cache_reset_headers)
        service = self.ows.get_service(tmp_req)
        invalidate_service(svc_name)

        def test_ops():
            run_check(test_requests)  # run all requests that triggers initial caching
            run_check(cache_requests)  # run them using caches, not triggering full ACL resolutions

        mock_service_cached, mock_service, mock_acl_cached, mock_acl = self.run_with_caching_mocks(service, test_ops)

        # There should be as many service resolution as there are requests, but only first one without cache fetches it.
        # ACL resolution should also occur once for each 'request=<>' permission.
        total_cached = len(cache_requests)
        total_no_cache = len(test_requests)
        total_calls = total_cached + total_no_cache
        utils.check_val_equal(mock_service_cached.call_count, total_calls,
                              msg="Cached service call expected for each request")
        utils.check_val_equal(mock_acl_cached.call_count, total_calls,
                              msg="Cached ACL resolution expected for each request")
        utils.check_val_equal(mock_service.call_count, 1,
                              msg="Real service call expected only for first call since it is always the same service")
        utils.check_val_equal(mock_acl.call_count, total_calls,
                              msg="Real ACL call expected every time (cache disabled in ACL region setting)")
