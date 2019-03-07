from magpie.api.api_rest_schemas import ServiceTypesAPI
from magpie.constants import get_constant
from magpie.common import JSON_TYPE
from magpie.__meta__ import __version__
from tests import utils, runner
import unittest
import os
CUR_DIR = os.path.dirname(__file__)

# define expected service types literally to ensure they are imported via the test execution
ALL_SERVICES_TYPES = [
    "api",
    "access",
    "geoserverwms",
    "ncwms",
    "thredds",
    "wfs",
    "wps",
]
TEST_SERVICE_IS_MODULE = "DynamicServiceFromIsModule"
TEST_SERVICE_NO_MODULE = "DynamicServiceFromNoModule"


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_SERVICES
class TestCase_MagpieServices_DynamicLoading(unittest.TestCase):
    """Test dynamic service implementation loading from config."""

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.cookies = None
        cls.headers = None
        cls.version = __version__
        # noinspection PyTypeChecker
        utils.warn_version(cls, "dynamic services by config", '0.10.0', skip=True)

        utils.check_val_is_in(get_constant('MAGPIE_SERVICES_PATHS'), [None, ''],
                              msg="Cannot have pre-defined 'MAGPIE_SERVICES_PATHS' to properly test service imports.")
        utils.check_val_is_in(get_constant('MAGPIE_SERVICES_FILTER'), [None, ''],
                              msg="Cannot have pre-defined 'MAGPIE_SERVICES_FILTER' to properly test service imports.")

    def login(self):
        app_url = utils.get_app_or_url(self)
        self.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        self.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        self.json_headers = {'Accept': JSON_TYPE, 'Content-Type': JSON_TYPE}
        self.headers, self.cookies = utils.check_or_try_login_user(app_url, self.usr, self.pwd,
                                                                   use_ui_form_submit=True, version=self.version)
        assert self.headers and self.cookies, "cannot run tests without logged in admin user"

    def test_load_normal(self):
        self.app = utils.get_test_magpie_app({'magpie.services_paths': ''})
        self.login()
        resp = utils.test_request(self.app, 'GET', ServiceTypesAPI.path, headers=self.headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        test = ALL_SERVICES_TYPES + [TEST_SERVICE_IS_MODULE, TEST_SERVICE_NO_MODULE]
        utils.check_all_equal(body['service_types'], test, any_order=True)

    def test_load_recursive_from_top_dir(self):
        self.app = utils.get_test_magpie_app({'magpie.services_paths': os.path.dirname(CUR_DIR)})
        self.login()
        resp = utils.test_request(self.app, 'GET', ServiceTypesAPI.path, headers=self.headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        test = ALL_SERVICES_TYPES + [TEST_SERVICE_IS_MODULE, TEST_SERVICE_NO_MODULE]
        utils.check_all_equal(body['service_types'], test, any_order=True)

    def test_load_from_is_module_dir(self):
        self.app = utils.get_test_magpie_app({'magpie.services_paths': os.path.join(CUR_DIR, 'services', 'is-module')})
        self.login()
        resp = utils.test_request(self.app, 'GET', ServiceTypesAPI.path, headers=self.headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        test = ALL_SERVICES_TYPES + [TEST_SERVICE_IS_MODULE]
        utils.check_all_equal(body['service_types'], test, any_order=True)

    def test_load_from_no_module_dir(self):
        self.app = utils.get_test_magpie_app({'magpie.services_paths': os.path.join(CUR_DIR, 'services', 'no-module')})
        self.login()
        resp = utils.test_request(self.app, 'GET', ServiceTypesAPI.path, headers=self.headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        test = ALL_SERVICES_TYPES + [TEST_SERVICE_NO_MODULE]
        utils.check_all_equal(body['service_types'], test, any_order=True)

    def test_load_with_filter_dynamic_service(self):
        test = ALL_SERVICES_TYPES + [TEST_SERVICE_NO_MODULE]
        opt = {
            'magpie.services_paths': os.path.join(CUR_DIR, 'services'),
            'magpie.services_filter': ','.join(test)
        }
        self.app = utils.get_test_magpie_app(opt)
        self.login()
        resp = utils.test_request(self.app, 'GET', ServiceTypesAPI.path, headers=self.headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_all_equal(body['service_types'], test, any_order=True)

    def test_load_with_multiple_file_paths(self):
        # TODO: implement
        self.skipTest(reason="not implemented")

    def test_load_with_multiple_dir_paths(self):
        # TODO: implement
        self.skipTest(reason="not implemented")

    def test_load_with_mixed_file_dir_paths(self):
        # TODO: implement
        self.skipTest(reason="not implemented")
