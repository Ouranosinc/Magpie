from pyramid.httpexceptions import HTTPNotFound

from magpie import __meta__
from magpie.adapter.magpieowssecurity import MagpieOWSSecurity, OWSAccessForbidden
from magpie.adapter.magpieservice import MagpieServiceStore
from magpie.constants import get_constant
from magpie.services import ServiceAPI
from tests import interfaces as ti, runner, utils


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_ADAPTER
@runner.MAGPIE_TEST_FUNCTIONAL
class TestAdapter(ti.SetupMagpieAdapter, ti.UserTestCase, ti.BaseTestCase):
    """
    Validation of general :class:`magpie.adapter.MagpieAdapter` operations and its underlying service/security handling.
    """

    __test__ = True

    @classmethod
    @utils.mock_get_settings
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.app = utils.get_test_magpie_app()
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.settings = cls.app.app.registry.settings

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

    @utils.mock_get_settings
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

    @utils.mock_get_settings
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

    @utils.mock_get_settings
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

    @utils.mock_get_settings
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


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_ADAPTER
@runner.MAGPIE_TEST_FUNCTIONAL
class TestAdapterCaching(ti.SetupMagpieAdapter, ti.UserTestCase, ti.BaseTestCase):
    """
    Test request parsing and :term:`ACL` resolution when caching is enabled.
    """
    # pylint: disable=C0103,invalid-name
    __test__ = True
    test_headers = None
    test_cookies = None
    cache_expire = 10
    cache_enabled = True
    cache_reset_headers = {"Cache-Control": "no-cache"}

    @classmethod
    @utils.mock_get_settings
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.settings = {}
        utils.setup_cache_settings(cls.settings, enabled=cls.cache_enabled, expire=cls.cache_expire)
        cls.app = utils.get_test_magpie_app(settings=cls.settings, setup_cache=False)
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")

        # following will be wiped on setup
        cls.test_user_name = "unittest-adapter-cache-user"
        cls.test_group_name = "unittest-adapter-cache-group"
        cls.test_service_name = "unittest-adapter-service"
        cls.test_service_type = ServiceAPI.service_type

        cls.setup_adapter()
        cls.setup_admin()

    @utils.mock_get_settings
    def setUp(self):
        ti.UserTestCase.setUp(self)
        self.setup_adapter()
        self.cookies = None
        self.headers, self.cookies = utils.check_or_try_login_user(self, self.usr, self.pwd, use_ui_form_submit=True)
        self.require = "cannot run tests without logged in user with '{}' permissions".format(self.grp)
        self.login_admin()
        utils.TestSetup.create_TestService(self)

    @utils.mock_get_settings
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
                req = self.mock_request(path, method="GET", headers=admin_no_cache, cookies=admin_cookies)
                utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [GET, {}]".format(path))

                # run many requests which should directly return the previously cached result
                req = self.mock_request(path, method="GET", headers=admin_headers, cookies=admin_cookies)
                msg = "Using [GET, {}]".format(path)
                for _ in range(number_calls):
                    utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

        utils.check_val_equal(mock_cached.call_count, number_calls + 1, msg="Cached call expected for each request")
        utils.check_val_equal(mock_service.call_count, 1, msg="Real call expected only on first run before caching")

    @utils.mock_get_settings
    def test_access_cached_service_by_other_user(self):
        pass
