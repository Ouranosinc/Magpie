import unittest
import pytest
import pyramid.testing
import yaml
import six
from six.moves.urllib.parse import urlparse
from distutils.version import LooseVersion
from magpie.api.api_rest_schemas import SwaggerGenerator
from magpie.constants import get_constant
from magpie.services import service_type_dict
from magpie.utils import get_twitcher_protected_service_url
from tests import utils, runner


# noinspection PyPep8Naming
@pytest.mark.api
@unittest.skipUnless(*runner.MAGPIE_TEST_API)
class Interface_MagpieAPI_NoAuth(object):
    """
    Interface class for unittests of Magpie API.
    Test any operation that do not require user AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
    """

    __test__ = False

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    @unittest.skipUnless(runner.MAGPIE_TEST_LOGIN, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('login'))
    def test_GetSession_Anonymous(self):
        resp = utils.test_request(self.url, 'GET', '/session', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(json_body['authenticated'], False)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_not_in('user', json_body)
        else:
            utils.check_val_not_in('user_name', json_body)
            utils.check_val_not_in('user_email', json_body)
            utils.check_val_not_in('group_names', json_body)

    def test_GetVersion(self):
        resp = utils.test_request(self.url, 'GET', '/version', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('db_version', json_body)
        utils.check_val_is_in('version', json_body)
        # server not necessarily at latest version, ensure at least format
        utils.check_val_equal(json_body['version'], self.version)
        utils.check_val_type(json_body['version'], six.string_types)
        version_parts = json_body['version'].split('.')
        utils.check_val_equal(len(version_parts), 3)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetCurrentUser(self):
        logged_user = get_constant('MAGPIE_LOGGED_USER')
        resp = utils.test_request(self.url, 'GET', '/users/{}'.format(logged_user), headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            utils.check_val_equal(json_body['user_name'], self.usr)


# noinspection PyPep8Naming
@unittest.skip("Not implemented.")
@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.api
@unittest.skipUnless(*runner.MAGPIE_TEST_API)
class Interface_MagpieAPI_UsersAuth(unittest.TestCase):
    """
    Interface class for unittests of Magpie API.
    Test any operation that require at least 'Users' group AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
    """

    __test__ = False

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()


# noinspection PyPep8Naming
@pytest.mark.api
@unittest.skipUnless(*runner.MAGPIE_TEST_API)
class Interface_MagpieAPI_AdminAuth(object):
    """
    Interface class for unittests of Magpie API.
    Test any operation that require at least 'administrator' group AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
    """

    __test__ = False

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    def tearDown(self):
        self.check_requirements()   # re-login as required in case test logged out the user with permissions
        utils.TestSetup.delete_TestServiceResource(self)
        utils.TestSetup.delete_TestService(self)
        utils.TestSetup.delete_TestUser(self)

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd,
                                                         use_ui_form_submit=True, version=cls.version)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    @classmethod
    def setup_test_values(cls):
        services_cfg = yaml.load(open(get_constant('MAGPIE_PROVIDERS_CONFIG_PATH'), 'r'))
        provider_services_info = services_cfg['providers']
        # filter impossible providers from possible previous version of remote server
        possible_service_types = utils.get_service_types_for_version(cls.version)
        cls.test_services_info = dict()
        for svc_name in provider_services_info:
            if provider_services_info[svc_name]['type'] in possible_service_types:
                cls.test_services_info[svc_name] = provider_services_info[svc_name]

        cls.test_service_name = u'magpie-unittest-service-api'
        cls.test_service_type = u'api'
        utils.TestSetup.create_TestService(cls)

        cls.test_resource_name = u'magpie-unittest-resource'
        test_service_res_perm_dict = service_type_dict[cls.test_service_type].resource_types_permissions
        test_service_resource_types = list(test_service_res_perm_dict.keys())
        assert len(test_service_resource_types), "test service must allow at least 1 sub-resource for test execution"
        cls.test_resource_type = test_service_resource_types[0]
        test_service_resource_perms = test_service_res_perm_dict[cls.test_resource_type]
        assert len(test_service_resource_perms), "test service must allow at least 1 sub-permission for test execution"
        cls.test_resource_perm = test_service_resource_perms[0]

        cls.test_group_name = u'magpie-unittest-dummy-group'
        cls.test_user_name = u'magpie-unittest-toto'
        cls.test_user_group = u'users'

    def setUp(self):
        self.check_requirements()
        utils.TestSetup.delete_TestServiceResource(self)
        utils.TestSetup.delete_TestService(self)
        utils.TestSetup.delete_TestUser(self)

    def test_GetAPI(self):
        resp = utils.test_request(self.url, 'GET', SwaggerGenerator.path, headers=self.json_headers)
        json_body = utils.get_json_body(resp)
        content_types = utils.get_response_content_types_list(resp)
        utils.check_val_is_in('application/json', content_types)
        utils.check_val_equal(resp.status_code, 200)
        utils.check_val_is_in('info', json_body)
        utils.check_val_is_in('version', json_body['info'])
        utils.check_val_equal(json_body['info']['version'], self.version)
        utils.check_val_is_in('paths', json_body)
        utils.check_val_is_in('host', json_body)
        utils.check_val_is_in('schemes', json_body)
        utils.check_val_is_in('tags', json_body)
        utils.check_val_is_in('basePath', json_body)
        utils.check_val_is_in('securityDefinitions', json_body)
        utils.check_val_is_in('swagger', json_body)
        utils.check_val_equal(json_body['swagger'], '2.0')

    @pytest.mark.login
    @unittest.skipUnless(runner.MAGPIE_TEST_LOGIN, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('login'))
    def test_GetSession_Administrator(self):
        resp = utils.test_request(self.url, 'GET', '/session', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(json_body['authenticated'], True)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_is_in('user', json_body)
            utils.check_val_equal(json_body['user']['user_name'], self.usr)
            utils.check_val_is_in(get_constant('MAGPIE_ADMIN_GROUP'), json_body['user']['group_names'])
            utils.check_val_type(json_body['user']['group_names'], list)
            utils.check_val_is_in('email', json_body['user'])
        else:
            utils.check_val_equal(json_body['user_name'], self.usr)
            utils.check_val_is_in(get_constant('MAGPIE_ADMIN_GROUP'), json_body['group_names'])
            utils.check_val_type(json_body['group_names'], list)
            utils.check_val_is_in('user_email', json_body)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetUsers(self):
        resp = utils.test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('user_names', json_body)
        utils.check_val_type(json_body['user_names'], list)
        utils.check_val_equal(len(json_body['user_names']) > 1, True)     # should have more than only 'anonymous'
        utils.check_val_is_in('anonymous', json_body['user_names'])       # anonymous always in users
        utils.check_val_is_in(self.usr, json_body['user_names'])          # current test user in users

    @pytest.mark.users
    @pytest.mark.defaults
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    @unittest.skipUnless(runner.MAGPIE_TEST_DEFAULTS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('defaults'))
    def test_ValidateDefaultUsers(self):
        resp = utils.test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        users = json_body['user_names']
        utils.check_val_is_in(get_constant('MAGPIE_ANONYMOUS_USER'), users)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_USER'), users)

    @classmethod
    def check_GetUserResourcesPermissions(cls, user_name, resource_id, query=None):
        query = '?{}'.format(query) if query else ''
        route = '/users/{usr}/resources/{res_id}/permissions{q}'.format(res_id=resource_id, usr=user_name, q=query)
        resp = utils.test_request(cls.url, 'GET', route, headers=cls.json_headers, cookies=cls.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('permission_names', json_body)
        utils.check_val_type(json_body['permission_names'], list)
        return json_body

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetCurrentUserResourcesPermissions(self):
        utils.TestSetup.create_TestService(self)
        json_body = utils.TestSetup.create_TestServiceResource(self)
        res_id = json_body['resource']['resource_id']
        self.check_GetUserResourcesPermissions(get_constant('MAGPIE_LOGGED_USER'), res_id)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetCurrentUserResourcesPermissions_Queries(self):
        if LooseVersion(self.version) < LooseVersion('0.7.0'):
            self.skipTest(reason="Queries not yet implemented in this version.")

        # setup test resources under service with permissions
        # Service/Resources              | Admin-User | Admin-Group | Anonym-User | Anonym-Group
        # ---------------------------------------------------------------------------------------
        # test-service                   | r          | r-m         |             | r
        #   |- test-resource (parent)    |            | r-m         |             |
        #       |- test-resource (child) |            |             | r-m         |
        json_body = utils.TestSetup.create_TestService(self)
        test_svc_res_id = json_body['service']['resource_id']
        json_body = utils.TestSetup.create_TestServiceResource(self)
        test_parent_res_id = json_body['resource']['resource_id']
        child_resource_name = self.test_resource_name + "-child"
        data_override = {
            "resource_name": child_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": test_parent_res_id
        }
        json_body = utils.TestSetup.create_TestServiceResource(self, data_override)
        test_child_res_id = json_body['resource']['resource_id']
        anonym_usr = get_constant('MAGPIE_ANONYMOUS_USER')
        anonym_grp = get_constant('MAGPIE_ANONYMOUS_GROUP')

        perm_recur = self.test_resource_perm
        perm_match = self.test_resource_perm + "-match"
        data_recur = {u'permission_name': perm_recur}
        data_match = {u'permission_name': perm_match}
        path = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=test_svc_res_id, usr=self.usr)
        utils.test_request(self.url, 'POST', path, data=data_recur, headers=self.json_headers, cookies=self.cookies)
        path = '/groups/{grp}/resources/{res_id}/permissions'.format(res_id=test_svc_res_id, grp=self.grp)
        utils.test_request(self.url, 'POST', path, data=data_match, headers=self.json_headers, cookies=self.cookies)
        path = '/groups/{grp}/resources/{res_id}/permissions'.format(res_id=test_parent_res_id, grp=self.grp)
        utils.test_request(self.url, 'POST', path, data=data_match, headers=self.json_headers, cookies=self.cookies)
        path = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=test_child_res_id, usr=anonym_usr)
        utils.test_request(self.url, 'POST', path, data=data_match, headers=self.json_headers, cookies=self.cookies)
        path = '/groups/{grp}/resources/{res_id}/permissions'.format(res_id=test_svc_res_id, grp=anonym_grp)
        utils.test_request(self.url, 'POST', path, data=data_recur, headers=self.json_headers, cookies=self.cookies)

        # tests
        q_groups = "inherit=true"
        q_effect = "effective=true"
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=None)
        utils.check_val_equal(json_body['permission_names'], [])
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=q_groups)
        utils.check_val_equal(json_body['permission_names'], [])
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=q_effect)
        utils.check_val_equal(json_body['permission_names'], [perm_recur])
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=None)
        utils.check_val_equal(json_body['permission_names'], [])
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=q_groups)
        utils.check_val_equal(json_body['permission_names'], [perm_match])
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=q_effect)
        utils.check_all_equal(json_body['permission_names'], [perm_recur, perm_match], any_order=True)
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=None)
        utils.check_val_equal(json_body['permission_names'], [perm_recur])
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=q_groups)
        utils.check_all_equal(json_body['permission_names'], [perm_recur, perm_match], any_order=True)
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=q_effect)
        utils.check_all_equal(json_body['permission_names'], [perm_recur, perm_match], any_order=True)

        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=None)
        utils.check_val_equal(json_body['permission_names'], [perm_match])
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=q_groups)
        utils.check_val_equal(json_body['permission_names'], [perm_match])
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=q_effect)
        utils.check_all_equal(json_body['permission_names'], [perm_recur, perm_match], any_order=True)
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=None)
        utils.check_val_equal(json_body['permission_names'], [])
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=q_groups)
        utils.check_val_equal(json_body['permission_names'], [])
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=q_effect)
        utils.check_val_equal(json_body['permission_names'], [perm_recur])
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=None)
        utils.check_val_equal(json_body['permission_names'], [])
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=q_groups)
        utils.check_val_equal(json_body['permission_names'], [perm_recur])
        json_body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=q_effect)
        utils.check_val_equal(json_body['permission_names'], [perm_recur])

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetUserResourcesPermissions(self):
        utils.TestSetup.create_TestService(self)
        json_body = utils.TestSetup.create_TestServiceResource(self)
        self.check_GetUserResourcesPermissions(self.usr, json_body['resource']['resource_id'])

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_PostUserResourcesPermissions_Created(self):
        resource_name = 'post_res_perm_created'
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

        data = {'resource_name': resource_name}
        body = utils.TestSetup.create_TestServiceResource(self, data_override=data)
        test_res_id = body['resource']['resource_id']

        # test permission creation
        path = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=test_res_id, usr=self.usr)
        data = {u'permission_name': self.test_resource_perm}
        resp = utils.test_request(self.url, 'POST', path, data=data, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 201, expected_method='POST')
        utils.check_val_is_in('permission_name', json_body)
        utils.check_val_is_in('resource_id', json_body)
        utils.check_val_is_in('user_id', json_body)
        utils.check_val_type(json_body['permission_name'], six.string_types)
        utils.check_val_type(json_body['resource_id'], int)
        utils.check_val_type(json_body['user_id'], int)

        # cleanup (delete sub resource should remove child permission)
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_PostUserResourcesPermissions_Conflict(self):
        resource_name = 'post_res_perm_conflict'
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

        data = {'resource_name': resource_name}
        body = utils.TestSetup.create_TestServiceResource(self, data_override=data)
        test_res_id = body['resource']['resource_id']

        path = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=test_res_id, usr=self.usr)
        data = {u'permission_name': self.test_resource_perm}
        utils.test_request(self.url, 'POST', path, data=data, headers=self.json_headers, cookies=self.cookies)
        json_body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_res_id)
        utils.check_val_is_in(self.test_resource_perm, json_body['permission_names'],
                              msg="Can't test for conflicting permissions if it doesn't exist first.")

        resp = utils.test_request(self.url, 'POST', path, data=data, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        json_body = utils.check_response_basic_info(resp, 409, expected_method='POST')
        utils.check_val_is_in('permission_name', json_body)
        utils.check_val_is_in('resource_id', json_body)
        utils.check_val_is_in('user_id', json_body)
        utils.check_val_type(json_body['permission_name'], six.string_types)
        utils.check_val_type(json_body['resource_id'], int)
        utils.check_val_type(json_body['user_id'], int)

        # cleanup (delete sub resource should remove child permission)
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetCurrentUserGroups(self):
        resp = utils.test_request(self.url, 'GET', '/users/current/groups',
                                  headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('group_names', json_body)
        utils.check_val_type(json_body['group_names'], list)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_GROUP'), json_body['group_names'])

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetUserInheritedResources(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        if LooseVersion(self.version) >= LooseVersion('0.7.0'):
            route = '/users/{usr}/inherited_resources'.format(usr=self.usr)
        else:
            route = '/users/{usr}/resources?inherit=true'.format(usr=self.usr)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies, timeout=20)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('resources', json_body)
        utils.check_val_type(json_body['resources'], dict)
        service_types = utils.get_service_types_for_version(self.version)
        utils.check_all_equal(json_body['resources'].keys(), service_types, any_order=True)
        for svc_type in json_body['resources']:
            for svc in json_body['resources'][svc_type]:
                svc_dict = json_body['resources'][svc_type][svc]
                utils.check_val_type(svc_dict, dict)
                utils.check_val_is_in('resource_id', svc_dict)
                utils.check_val_is_in('service_name', svc_dict)
                utils.check_val_is_in('service_type', svc_dict)
                utils.check_val_is_in('public_url', svc_dict)
                utils.check_val_is_in('permission_names', svc_dict)
                utils.check_val_is_in('resources', svc_dict)
                utils.check_val_type(svc_dict['resource_id'], int)
                utils.check_val_type(svc_dict['service_name'], six.string_types)
                utils.check_val_type(svc_dict['service_type'], six.string_types)
                utils.check_val_type(svc_dict['public_url'], six.string_types)
                utils.check_val_type(svc_dict['permission_names'], list)
                utils.check_val_type(svc_dict['resources'], dict)
                if LooseVersion(self.version) >= LooseVersion('0.7.0'):
                    utils.check_val_is_in('service_sync_type', svc_dict)
                    utils.check_val_type(svc_dict['service_sync_type'], utils.OptionalStringType)
                    utils.check_val_not_in('service_url', svc_dict,
                                           msg="Services under user routes shouldn't show private url.")
                else:
                    utils.check_val_is_in('service_url', svc_dict)
                    utils.check_val_type(svc_dict['service_url'], six.string_types)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetUserServices(self):
        route = '/users/{usr}/services'.format(usr=self.usr)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('services', json_body)
        services = json_body['services']
        utils.check_val_type(services, dict)
        service_types = utils.get_service_types_for_version(self.version)
        # as of version '0.7.0', visible services depend on the connected user permissions,
        # so all services types not necessarily returned in the response
        if LooseVersion(self.version) < LooseVersion('0.7.0'):
            utils.check_all_equal(services.keys(), service_types, any_order=True)
        for svc_type in services:
            utils.check_val_is_in(svc_type, service_types)  # one of valid service types
            for svc in services[svc_type]:
                svc_dict = services[svc_type][svc]
                utils.check_val_type(svc_dict, dict)
                utils.check_val_is_in('resource_id', svc_dict)
                utils.check_val_is_in('service_name', svc_dict)
                utils.check_val_is_in('service_type', svc_dict)
                utils.check_val_is_in('public_url', svc_dict)
                utils.check_val_is_in('permission_names', svc_dict)
                utils.check_val_type(svc_dict['resource_id'], int)
                utils.check_val_type(svc_dict['service_name'], six.string_types)
                utils.check_val_type(svc_dict['service_type'], six.string_types)
                utils.check_val_type(svc_dict['public_url'], six.string_types)
                utils.check_val_type(svc_dict['permission_names'], list)
                if LooseVersion(self.version) >= LooseVersion('0.7.0'):
                    utils.check_val_is_in('service_sync_type', svc_dict)
                    utils.check_val_type(svc_dict['service_sync_type'], utils.OptionalStringType)
                    utils.check_val_not_in('service_url', svc_dict,
                                           msg="Services under user routes shouldn't show private url.")
                else:
                    utils.check_val_is_in('service_url', svc_dict)
                    utils.check_val_type(svc_dict['service_url'], six.string_types)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetUserServiceResources(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        route = '/users/{usr}/services/{svc}/resources'.format(usr=self.usr, svc=self.test_service_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('service', json_body)
        svc_dict = json_body['service']
        utils.check_val_type(svc_dict, dict)
        utils.check_val_is_in('resource_id', svc_dict)
        utils.check_val_is_in('service_name', svc_dict)
        utils.check_val_is_in('service_type', svc_dict)
        utils.check_val_is_in('public_url', svc_dict)
        utils.check_val_is_in('permission_names', svc_dict)
        utils.check_val_is_in('resources', svc_dict)
        utils.check_val_type(svc_dict['resource_id'], int)
        utils.check_val_type(svc_dict['service_name'], six.string_types)
        utils.check_val_type(svc_dict['service_type'], six.string_types)
        utils.check_val_type(svc_dict['public_url'], six.string_types)
        utils.check_val_type(svc_dict['permission_names'], list)
        utils.check_val_type(svc_dict['resources'], dict)
        if LooseVersion(self.version) >= LooseVersion('0.7.0'):
            utils.check_val_is_in('service_sync_type', svc_dict)
            utils.check_val_type(svc_dict['service_sync_type'], utils.OptionalStringType)
            utils.check_val_not_in('service_url', svc_dict)
        else:
            utils.check_val_is_in('service_url', svc_dict)
            utils.check_val_type(svc_dict['service_url'], six.string_types)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_PostUsers(self):
        json_body = utils.TestSetup.create_TestUser(self)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_is_in('user', json_body)
            utils.check_val_is_in('user_name', json_body['user'])
            utils.check_val_type(json_body['user']['user_name'], six.string_types)
            utils.check_val_is_in('email', json_body['user'])
            utils.check_val_type(json_body['user']['email'], six.string_types)
            utils.check_val_is_in('group_names', json_body['user'])
            utils.check_val_type(json_body['user']['group_names'], list)

        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(self.test_user_name, users)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_PutUsers_nothing(self):
        utils.TestSetup.create_TestUser(self)
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'PUT', route, headers=self.json_headers, cookies=self.cookies, data={},
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method='PUT')

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_PutUsers_username(self):
        utils.TestSetup.create_TestUser(self)
        new_name = self.test_user_name + '-new'

        # cleanup in case the updated username already exists (ex: previous test execution failure)
        route = '/users/{usr}'.format(usr=new_name)
        resp = utils.test_request(self.url, 'DELETE', route, headers=self.json_headers, cookies=self.cookies)
        utils.check_val_is_in(resp.status_code, [200, 404])

        # update existing user name
        data = {'user_name': new_name}
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'PUT', route, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 200, expected_method='PUT')

        # validate change of user name
        route = '/users/{usr}'.format(usr=new_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(body['user']['user_name'], new_name)

        # validate removed previous user name
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method='GET')

        # validate effective new user name
        utils.check_or_try_logout_user(self.url)
        headers, cookies = utils.check_or_try_login_user(self.url, username=new_name, password=self.test_user_name,
                                                         use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self.url, 'GET', '/session', headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(body['authenticated'], True)
        utils.check_val_equal(body['user']['user_name'], new_name)

        # validate ineffective previous user name
        utils.check_or_try_logout_user(self.url)
        headers, cookies = utils.check_or_try_login_user(self.url,
                                                         username=self.test_user_name, password=self.test_user_name,
                                                         use_ui_form_submit=True, version=self.version)
        utils.check_val_equal(cookies, {}, msg="Cookies should be empty from login failure.")
        resp = utils.test_request(self.url, 'GET', '/session', headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(body['authenticated'], False)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_PutUsers_email(self):
        utils.TestSetup.create_TestUser(self)
        new_email = 'toto@new-email.lol'
        data = {'email': new_email}
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'PUT', route, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 200, expected_method='PUT')

        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(body['user']['email'], new_email)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_PutUsers_password(self):
        utils.TestSetup.create_TestUser(self)
        old_password = self.test_user_name
        new_password = 'n0t-SO-ez-2-Cr4cK'
        data = {'password': new_password}
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'PUT', route, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 200, expected_method='PUT')
        utils.check_or_try_logout_user(self.url)

        # validate that the new password is effective
        headers, cookies = utils.check_or_try_login_user(self.url, username=self.test_user_name, password=new_password,
                                                         use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self.url, 'GET', '/session', headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(body['authenticated'], True)
        utils.check_val_equal(body['user']['user_name'], self.test_user_name)
        utils.check_or_try_logout_user(self.url)

        # validate that previous password is ineffective
        headers, cookies = utils.check_or_try_login_user(self.url, username=self.test_user_name, password=old_password,
                                                         use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self.url, 'GET', '/session', headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_equal(body['authenticated'], False)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetUser_existing(self):
        utils.TestSetup.create_TestUser(self)

        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_is_in('user', json_body)
            utils.check_val_is_in('user_name', json_body['user'])
            utils.check_val_type(json_body['user']['user_name'], six.string_types)
            utils.check_val_is_in('email', json_body['user'])
            utils.check_val_type(json_body['user']['email'], six.string_types)
            utils.check_val_is_in('group_names', json_body['user'])
            utils.check_val_type(json_body['user']['group_names'], list)
        else:
            utils.check_val_is_in('user_name', json_body)
            utils.check_val_type(json_body['user_name'], six.string_types)
            utils.check_val_is_in('email', json_body)
            utils.check_val_type(json_body['email'], six.string_types)
            utils.check_val_is_in('group_names', json_body)
            utils.check_val_type(json_body['group_names'], list)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetUser_missing(self):
        utils.TestSetup.check_NonExistingTestUser(self)
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers,
                                  cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method='GET')

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('users'))
    def test_GetCurrentUser(self):
        utils.TestSetup.check_NonExistingTestUser(self)
        logged_user = get_constant('MAGPIE_LOGGED_USER')
        resp = utils.test_request(self.url, 'GET', '/users/{}'.format(logged_user),
                                  headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            utils.check_val_equal(json_body['user_name'], self.usr)

    @pytest.mark.groups
    @pytest.mark.defaults
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('groups'))
    @unittest.skipUnless(runner.MAGPIE_TEST_DEFAULTS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('defaults'))
    def test_ValidateDefaultGroups(self):
        resp = utils.test_request(self.url, 'GET', '/groups', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        groups = json_body['group_names']
        utils.check_val_is_in(get_constant('MAGPIE_ANONYMOUS_GROUP'), groups)
        utils.check_val_is_in(get_constant('MAGPIE_USERS_GROUP'), groups)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_GROUP'), groups)

    @pytest.mark.groups
    @unittest.skipUnless(runner.MAGPIE_TEST_GROUPS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('groups'))
    def test_PostUserGroup_assign(self):
        utils.TestSetup.delete_TestGroup(self)  # setup as required
        utils.TestSetup.create_TestGroup(self)  # actual test
        utils.TestSetup.delete_TestGroup(self)  # cleanup

    @pytest.mark.groups
    @unittest.skipUnless(runner.MAGPIE_TEST_GROUPS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('groups'))
    def test_PostUserGroup_not_found(self):
        route = '/users/{usr}/groups'.format(usr=get_constant('MAGPIE_ADMIN_USER'))
        data = {'group_name': 'not_found'}
        resp = utils.test_request(self.url, 'POST', route, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 404, expected_method='POST')

    @pytest.mark.groups
    @unittest.skipUnless(runner.MAGPIE_TEST_GROUPS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('groups'))
    def test_PostUserGroup_conflict(self):
        route = '/users/{usr}/groups'.format(usr=get_constant('MAGPIE_ADMIN_USER'))
        data = {'group_name': get_constant('MAGPIE_ADMIN_GROUP')}
        resp = utils.test_request(self.url, 'POST', route,  expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 409, expected_method='POST')

    @pytest.mark.groups
    @unittest.skipUnless(runner.MAGPIE_TEST_GROUPS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('groups'))
    def test_GetGroupUsers(self):
        route = '/groups/{grp}/users'.format(grp=get_constant('MAGPIE_ADMIN_GROUP'))
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('user_names', json_body)
        utils.check_val_type(json_body['user_names'], list)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_USER'), json_body['user_names'])
        utils.check_val_is_in(self.usr, json_body['user_names'])

    @pytest.mark.groups
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('groups'))
    def test_GetGroupServices(self):
        route = '/groups/{grp}/services'.format(grp=self.grp)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('services', json_body)
        services = json_body['services']
        utils.check_val_type(services, dict)
        service_types = utils.get_service_types_for_version(self.version)
        # as of version '0.7.0', visible services depend on the connected user permissions,
        # so all services types not necessarily returned in the response
        if LooseVersion(self.version) < LooseVersion('0.7.0'):
            utils.check_all_equal(services.keys(), service_types, any_order=True)
        for svc_type in services:
            utils.check_val_is_in(svc_type, service_types)  # one of valid service types
            for svc in services[svc_type]:
                svc_dict = services[svc_type][svc]
                utils.check_val_type(svc_dict, dict)
                utils.check_val_is_in('resource_id', svc_dict)
                utils.check_val_is_in('service_name', svc_dict)
                utils.check_val_is_in('service_type', svc_dict)
                utils.check_val_is_in('public_url', svc_dict)
                utils.check_val_is_in('permission_names', svc_dict)
                utils.check_val_type(svc_dict['resource_id'], int)
                utils.check_val_type(svc_dict['service_name'], six.string_types)
                utils.check_val_type(svc_dict['service_type'], six.string_types)
                utils.check_val_type(svc_dict['public_url'], six.string_types)
                utils.check_val_type(svc_dict['permission_names'], list)
                if LooseVersion(self.version) >= LooseVersion('0.7.0'):
                    utils.check_val_is_in('service_sync_type', svc_dict)
                    utils.check_val_type(svc_dict['service_sync_type'], utils.OptionalStringType)
                    utils.check_val_not_in('service_url', svc_dict)
                else:
                    utils.check_val_is_in('service_url', svc_dict)
                    utils.check_val_type(svc_dict['service_url'], six.string_types)

    @pytest.mark.groups
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('groups'))
    def test_GetGroupServiceResources(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        route = '/groups/{grp}/services/{svc}/resources'.format(grp=self.grp, svc=self.test_service_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in('service', json_body)
        svc_dict = json_body['service']
        utils.check_val_type(svc_dict, dict)
        utils.check_val_is_in('resource_id', svc_dict)
        utils.check_val_is_in('service_name', svc_dict)
        utils.check_val_is_in('service_type', svc_dict)
        utils.check_val_is_in('public_url', svc_dict)
        utils.check_val_is_in('permission_names', svc_dict)
        utils.check_val_is_in('resources', svc_dict)
        utils.check_val_type(svc_dict['resource_id'], int)
        utils.check_val_type(svc_dict['service_name'], six.string_types)
        utils.check_val_type(svc_dict['service_type'], six.string_types)
        utils.check_val_type(svc_dict['public_url'], six.string_types)
        utils.check_val_type(svc_dict['permission_names'], list)
        utils.check_val_type(svc_dict['resources'], dict)
        if LooseVersion(self.version) >= LooseVersion('0.7.0'):
            utils.check_val_is_in('service_sync_type', svc_dict)
            utils.check_val_type(svc_dict['service_sync_type'], utils.OptionalStringType)
            utils.check_val_not_in('service_url', svc_dict)
        else:
            utils.check_val_is_in('service_url', svc_dict)
            utils.check_val_type(svc_dict['service_url'], six.string_types)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    def test_PostService_ResponseFormat(self):
        json_body = utils.TestSetup.create_TestService(self)
        utils.check_val_is_in('service', json_body)
        utils.check_val_type(json_body['service'], dict)
        utils.check_val_is_in('resource_id', json_body['service'])
        utils.check_val_is_in('public_url', json_body['service'])
        utils.check_val_is_in('service_url', json_body['service'])
        utils.check_val_is_in('service_name', json_body['service'])
        utils.check_val_is_in('service_type', json_body['service'])
        utils.check_val_is_in('permission_names', json_body['service'])
        utils.check_val_type(json_body['service']['resource_id'], int)
        utils.check_val_type(json_body['service']['public_url'], six.string_types)
        utils.check_val_type(json_body['service']['service_url'], six.string_types)
        utils.check_val_type(json_body['service']['service_name'], six.string_types)
        utils.check_val_type(json_body['service']['service_type'], six.string_types)
        utils.check_val_type(json_body['service']['permission_names'], list)
        if LooseVersion(self.version) >= LooseVersion('0.7.0'):
            utils.check_val_is_in('service_sync_type', json_body['service'])
            utils.check_val_type(json_body['service']['service_sync_type'], utils.OptionalStringType)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    def test_GetServiceResources(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        svc_dict = json_body[self.test_service_name]
        utils.check_val_is_in(self.test_service_name, json_body)
        utils.check_val_type(json_body[self.test_service_name], dict)
        utils.check_val_is_in('resource_id', svc_dict)
        utils.check_val_is_in('service_name', svc_dict)
        utils.check_val_is_in('service_type', svc_dict)
        utils.check_val_is_in('service_url', svc_dict)
        utils.check_val_is_in('public_url', svc_dict)
        utils.check_val_is_in('permission_names', svc_dict)
        utils.check_val_is_in('resources', svc_dict)
        utils.check_val_type(svc_dict['resource_id'], int)
        utils.check_val_type(svc_dict['service_name'], six.string_types)
        utils.check_val_type(svc_dict['service_url'], six.string_types)
        utils.check_val_type(svc_dict['service_type'], six.string_types)
        utils.check_val_type(svc_dict['public_url'], six.string_types)
        utils.check_val_type(svc_dict['permission_names'], list)
        utils.check_resource_children(svc_dict['resources'], svc_dict['resource_id'], svc_dict['resource_id'])
        if LooseVersion(self.version) >= LooseVersion('0.7.0'):
            utils.check_val_is_in('service_sync_type', svc_dict)
            utils.check_val_type(svc_dict['service_sync_type'], utils.OptionalStringType)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    def test_GetServicePermissions(self):
        services_list = utils.TestSetup.get_RegisteredServicesList(self)

        for svc in services_list:
            svc_name = svc['service_name']
            service_perms = service_type_dict[svc['service_type']].permission_names
            route = '/services/{svc}/permissions'.format(svc=svc_name)
            resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
            json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
            utils.check_val_is_in('permission_names', json_body)
            utils.check_val_type(json_body['permission_names'], list)
            utils.check_all_equal(json_body['permission_names'], service_perms, any_order=True)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    def test_PostServiceResources_DirectResource_NoParentID(self):
        utils.TestSetup.create_TestService(self)
        resources_prior = utils.TestSetup.get_TestServiceDirectResources(self)
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        json_body = utils.TestSetup.create_TestServiceResource(self)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_is_in('resource', json_body)
            json_body = json_body['resource']
        utils.check_val_is_in('resource_id', json_body)
        utils.check_val_is_in('resource_name', json_body)
        utils.check_val_is_in('resource_type', json_body)
        utils.check_val_not_in(json_body['resource_id'], resources_prior_ids)
        utils.check_val_equal(json_body['resource_name'], self.test_resource_name)
        utils.check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    def test_PostServiceResources_DirectResource_WithParentID(self):
        utils.TestSetup.create_TestService(self)
        resources_prior = utils.TestSetup.get_TestServiceDirectResources(self)
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        service_id = utils.TestSetup.get_ExistingTestServiceInfo(self)['resource_id']
        extra_data = {"parent_id": service_id}
        json_body = utils.TestSetup.create_TestServiceResource(self, extra_data)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_is_in('resource', json_body)
            json_body = json_body['resource']
        utils.check_val_is_in('resource_id', json_body)
        utils.check_val_is_in('resource_name', json_body)
        utils.check_val_is_in('resource_type', json_body)
        utils.check_val_not_in(json_body['resource_id'], resources_prior_ids)
        utils.check_val_equal(json_body['resource_name'], self.test_resource_name)
        utils.check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    def test_PostServiceResources_ChildrenResource_ParentID(self):
        # create the direct resource
        json_body = utils.TestSetup.create_TestServiceResource(self)
        resources = utils.TestSetup.get_TestServiceDirectResources(self)
        resources_ids = [res['resource_id'] for res in resources]
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            test_resource_id = json_body['resource']['resource_id']
        else:
            test_resource_id = json_body['resource_id']
        utils.check_val_is_in(test_resource_id, resources_ids,
                              msg="service resource must exist to create children resource")

        # create the children resource under the direct resource and validate response info
        child_resource_name = self.test_resource_name + "-children"
        data_override = {
            "resource_name": child_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": test_resource_id
        }
        json_body = utils.TestSetup.create_TestServiceResource(self, data_override)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_is_in('resource', json_body)
            utils.check_val_type(json_body['resource'], dict)
            json_body = json_body['resource']
        utils.check_val_is_in('resource_id', json_body)
        utils.check_val_not_in(json_body['resource_id'], resources_ids)
        utils.check_val_is_in('resource_name', json_body)
        utils.check_val_equal(json_body['resource_name'], child_resource_name)
        utils.check_val_is_in('resource_type', json_body)
        utils.check_val_equal(json_body['resource_type'], self.test_resource_type)

        # validate created children resource info
        service_root_id = utils.TestSetup.get_ExistingTestServiceInfo(self)['resource_id']
        child_resource_id = json_body['resource_id']
        route = '/resources/{res_id}'.format(res_id=child_resource_id)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        utils.check_val_is_in(str(child_resource_id), json_body)
        resource_body = json_body[str(child_resource_id)]
        utils.check_val_equal(resource_body['root_service_id'], service_root_id)
        utils.check_val_equal(resource_body['parent_id'], test_resource_id)
        utils.check_val_equal(resource_body['resource_id'], child_resource_id)
        utils.check_val_equal(resource_body['resource_name'], child_resource_name)
        utils.check_val_equal(resource_body['resource_type'], self.test_resource_type)
        utils.check_val_type(resource_body['children'], dict)
        utils.check_val_equal(len(resource_body['children']), 0)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    def test_PostServiceResources_DirectResource_Conflict(self):
        utils.TestSetup.create_TestServiceResource(self)
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        data = {"resource_name": self.test_resource_name, "resource_type": self.test_resource_type}
        resp = utils.test_request(self.url, 'POST', route, headers=self.json_headers,
                                  cookies=self.cookies, json=data, expect_errors=True)
        json_body = utils.check_response_basic_info(resp, 409, expected_method='POST')
        utils.check_error_param_structure(json_body, version=self.version,
                                          is_param_value_literal_unicode=True, param_compare_exists=True,
                                          param_value=self.test_resource_name, param_name=u'resource_name')

    @pytest.mark.services
    @pytest.mark.defaults
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('services'))
    @unittest.skipUnless(runner.MAGPIE_TEST_DEFAULTS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('defaults'))
    def test_ValidateDefaultServiceProviders(self):
        services_list = utils.TestSetup.get_RegisteredServicesList(self)

        # ensure that registered services information are all matching the providers in config file
        # ignore registered services not from providers as their are not explicitly required from the config
        for svc in services_list:
            svc_name = svc['service_name']
            if svc_name in self.test_services_info:
                utils.check_val_equal(svc['service_type'], self.test_services_info[svc_name]['type'])
                hostname = utils.get_hostname(self.url)
                # private service URL should match format of Magpie (schema/host)
                svc_url = self.test_services_info[svc_name]['url'].replace('${HOSTNAME}', hostname)
                utils.check_val_equal(svc['service_url'], svc_url)
                # public service URL should match Twitcher config, but ignore schema that depends on each server config
                twitcher_svc_url = get_twitcher_protected_service_url(svc_name, hostname=hostname)
                twitcher_parsed_url = urlparse(twitcher_svc_url)
                twitcher_test_url = twitcher_parsed_url.netloc + twitcher_parsed_url.path
                svc_parsed_url = urlparse(svc['public_url'])
                svc_test_public_url = svc_parsed_url.netloc + svc_parsed_url.path
                utils.check_val_equal(svc_test_public_url, twitcher_test_url)

        # ensure that no providers are missing from registered services
        registered_svc_names = [svc['service_name'] for svc in services_list]
        for svc_name in self.test_services_info:
            utils.check_val_is_in(svc_name, registered_svc_names)

        # ensure that 'getcapabilities' permission is given to anonymous for applicable services
        anonymous = get_constant('MAGPIE_ANONYMOUS_USER')
        services_list_getcap = [svc for svc in services_list if 'getcapabilities' in svc['permission_names']]
        route = '/users/{usr}/services'.format(usr=anonymous)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200, expected_method='GET')
        services_body = json_body['services']
        for svc in services_list_getcap:
            svc_name = svc['service_name']
            svc_type = svc['service_type']
            msg = "Service `{name}` of type `{type}` is expected to have `{perm}` permissions for user `{usr}`" \
                  .format(name=svc_name, type=svc_type, perm='getcapabilities', usr=anonymous)
            utils.check_val_is_in(svc_name, services_body[svc_type], msg=msg)
            utils.check_val_is_in('getcapabilities', services_body[svc_type][svc_name]['permission_names'])

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('resources'))
    def test_PostResources_DirectServiceResource(self):
        utils.TestSetup.create_TestService(self)
        service_info = utils.TestSetup.get_ExistingTestServiceInfo(self)
        service_resource_id = service_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_display_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_resource_id
        }
        resp = utils.test_request(self.url, 'POST', '/resources',
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = utils.check_response_basic_info(resp, 201, expected_method='POST')
        utils.check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type,
                                            self.test_resource_name, self.version)

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('resources'))
    def test_PostResources_DirectServiceResourceOptional(self):
        utils.TestSetup.create_TestService(self)
        service_info = utils.TestSetup.get_ExistingTestServiceInfo(self)
        service_resource_id = service_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            # resource_display_name should default to self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_resource_id
        }
        resp = utils.test_request(self.url, 'POST', '/resources',
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = utils.check_response_basic_info(resp, 201, expected_method='POST')
        utils.check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type,
                                            self.test_resource_name, self.version)

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('resources'))
    def test_PostResources_ChildrenResource(self):
        resource_info = utils.TestSetup.create_TestServiceResource(self)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            direct_resource_id = resource_info['resource']['resource_id']
        else:
            direct_resource_id = resource_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_display_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": direct_resource_id
        }
        resp = utils.test_request(self.url, 'POST', '/resources',
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = utils.check_response_basic_info(resp, 201, expected_method='POST')
        utils.check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type,
                                            self.test_resource_name, self.version)

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('resources'))
    def test_PostResources_MissingParentID(self):
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = utils.test_request(self.url, 'POST', '/resources',
                                  headers=self.json_headers, cookies=self.cookies, data=data, expect_errors=True)
        json_body = utils.check_response_basic_info(resp, 422, expected_method='POST')
        utils.check_error_param_structure(json_body, version=self.version,
                                          param_name='parent_id', param_value=repr(None))

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('resources'))
    def test_DeleteResource(self):
        json_body = utils.TestSetup.create_TestServiceResource(self)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            resource_id = json_body['resource']['resource_id']
        else:
            resource_id = json_body['resource_id']

        route = '/resources/{res_id}'.format(res_id=resource_id)
        resp = utils.test_request(self.url, 'DELETE', route, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method='DELETE')
        utils.TestSetup.check_NonExistingTestServiceResource(self)


# noinspection PyPep8Naming
@pytest.mark.ui
@unittest.skipUnless(*runner.MAGPIE_TEST_UI)
class Interface_MagpieUI_NoAuth(object):
    """
    Interface class for unittests of Magpie UI.
    Test any operation that do not require user AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
    """

    __test__ = False

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/login')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewUsers(self):
        utils.TestSetup.check_Unauthorized(self, method='GET', path='/ui/users')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewGroups(self):
        utils.TestSetup.check_Unauthorized(self, method='GET', path='/ui/groups')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewServices(self):
        utils.TestSetup.check_Unauthorized(self, method='GET', path='/ui/services/default')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewServicesOfType(self):
        path = '/ui/services/{}'.format(self.test_service_type)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditUser(self):
        path = '/ui/users/{}/default'.format(self.test_user)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditGroup(self):
        path = '/ui/groups/{}/default'.format(self.test_group)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditService(self):
        path = '/ui/services/{type}/{name}'.format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_AddUser(self):
        path = '/ui/users/add'
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)
        utils.TestSetup.check_Unauthorized(self, method='POST', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_AddGroup(self):
        path = '/ui/groups/add'
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)
        utils.TestSetup.check_Unauthorized(self, method='POST', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_AddService(self):
        path = '/ui/services/{}/add'.format(self.test_service_type)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)
        utils.TestSetup.check_Unauthorized(self, method='POST', path=path)


# noinspection PyPep8Naming
@pytest.mark.ui
@unittest.skipUnless(*runner.MAGPIE_TEST_UI)
class Interface_MagpieUI_AdminAuth(object):
    """
    Interface class for unittests of Magpie UI.
    Test any operation that require at least 'administrator' group AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
    """

    __test__ = False

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/login')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewUsers(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/users')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewGroups(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/groups')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewServices(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/services/default')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_ViewServicesOfType(self):
        path = '/ui/services/{}'.format(self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditUser(self):
        path = '/ui/users/{}/default'.format(self.test_user)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditUserService(self):
        path = '/ui/users/{usr}/{type}'.format(usr=self.test_user, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditGroup(self):
        path = '/ui/groups/{}/default'.format(self.test_group)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditGroupService(self):
        path = '/ui/groups/{grp}/{type}'.format(grp=self.test_group, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_EditService(self):
        path = '/ui/services/{type}/{name}'.format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_AddUser(self):
        path = '/ui/users/add'
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)
        utils.TestSetup.check_UpStatus(self, method='POST', path=path)  # empty fields, same page but 'incorrect'

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_AddGroup(self):
        path = '/ui/groups/add'
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)
        utils.TestSetup.check_UpStatus(self, method='POST', path=path)  # empty fields, same page but 'incorrect'

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('status'))
    def test_AddService(self):
        path = '/ui/services/{}/add'.format(self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)
        utils.TestSetup.check_UpStatus(self, method='POST', path=path)  # empty fields, same page but 'incorrect'
