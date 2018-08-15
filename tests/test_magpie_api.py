#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_api
----------------------------------

Tests for `magpie.api` module.
"""

import unittest
import pytest
import pyramid.testing
import yaml
import six
from distutils.version import LooseVersion
from six.moves.urllib.parse import urlparse
from magpie.services import service_type_dict
from magpie.register import get_twitcher_protected_service_url
from magpie.api.api_rest_schemas import SwaggerGenerator
from magpie.constants import get_constant
from magpie import __meta__
from tests import utils, runner


@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieAPI_NoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = utils.get_headers_content_type(cls.app, 'application/json')
        cls.version = __meta__.__version__
        cls.cookies = None
        cls.usr = get_constant('MAGPIE_ANONYMOUS_USER')

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    @unittest.skipUnless(runner.MAGPIE_TEST_LOGIN, reason="Skip 'login' tests requested.")
    def test_GetSession_Anonymous(self):
        resp = utils.test_request(self.app, 'GET', '/session', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(json_body['authenticated'], False)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_not_in('user', json_body)
        else:
            utils.check_val_not_in('user_name', json_body)
            utils.check_val_not_in('user_email', json_body)
            utils.check_val_not_in('group_names', json_body)

    def test_GetVersion(self):
        resp = utils.test_request(self.app, 'GET', '/version', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in('db_version', json_body)
        utils.check_val_is_in('version', json_body)
        utils.check_val_equal(json_body['version'], self.version)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUser(self):
        logged_user = get_constant('MAGPIE_LOGGED_USER')
        resp = utils.test_request(self.url, 'GET', '/users/{}'.format(logged_user), headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            utils.check_val_equal(json_body['user_name'], self.usr)


@unittest.skip("Not implemented.")
@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieAPI_UsersAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Users' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()


@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieAPI_AdminAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.json_headers = utils.get_headers_content_type(cls.app, 'application/json')
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        # TODO: fix UI views so that they can be 'found' directly in the WebTest.TestApp
        # NOTE: localhost magpie has to be running for following login call to work
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd,
                                                                 use_ui_form_submit=True, version=cls.version)
        cls.require = "cannot run tests without logged in '{}' user".format(get_constant('MAGPIE_ADMIN_GROUP'))
        assert cls.headers and cls.cookies, cls.require

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies and cls.app.cookies, cls.require

    def setUp(self):
        self.check_requirements()

    def test_GetAPI(self):
        resp = utils.test_request(self.app, 'GET', SwaggerGenerator.path, headers=self.json_headers)
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

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUsers(self):
        resp = utils.test_request(self.app, 'GET', '/users', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in('user_names', json_body)
        utils.check_val_is_in('anonymous', json_body['user_names'])       # anonymous always in users
        utils.check_val_equal(len(json_body['user_names']) > 1, True)     # should have more than only 'anonymous'


@pytest.mark.api
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason="Skip 'remote' tests requested.")
class TestMagpieAPI_NoAuthRemote(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.json_headers = utils.get_headers_content_type(cls.url, 'application/json')
        cls.cookies = None
        cls.usr = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.version = utils.TestSetup.get_Version(cls)

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    @unittest.skipUnless(runner.MAGPIE_TEST_LOGIN, reason="Skip 'login' tests requested.")
    def test_GetSession_Anonymous(self):
        resp = utils.test_request(self.url, 'GET', '/session', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(json_body['authenticated'], False)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_not_in('user', json_body)
        else:
            utils.check_val_not_in('user_name', json_body)
            utils.check_val_not_in('user_email', json_body)
            utils.check_val_not_in('group_names', json_body)

    def test_GetVersion(self):
        resp = utils.test_request(self.url, 'GET', '/version', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in('db_version', json_body)
        utils.check_val_is_in('version', json_body)
        # server not necessarily at latest version, ensure at least format
        #utils.check_val_equal(json_body['version'], magpie.__meta__.__version__)
        utils.check_val_type(json_body['version'], six.string_types)
        version_parts = json_body['version'].split('.')
        utils.check_val_equal(len(version_parts), 3)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUser(self):
        resp = utils.test_request(self.url, 'GET', '/users/current', headers=self.json_headers)
        json_body = utils.check_response_basic_info(resp, 200)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            utils.check_val_equal(json_body['user_name'], self.usr)


@pytest.mark.api
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason="Skip 'remote' tests requested.")
class TestMagpieAPI_AdminAuthRemote(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(get_constant('MAGPIE_ADMIN_GROUP'))
        cls.json_headers = utils.get_headers_content_type(cls.url, 'application/json')
        cls.version = utils.TestSetup.get_Version(cls)
        cls.check_requirements()
        cls.get_test_values()

    @classmethod
    def tearDownClass(cls):
        utils.TestSetup.delete_TestServiceResource(cls)
        utils.TestSetup.delete_TestUser(cls)
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd, version=cls.version)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    @classmethod
    def get_test_values(cls):
        services_cfg = yaml.load(open(get_constant('MAGPIE_PROVIDERS_CONFIG_PATH'), 'r'))
        provider_services_info = services_cfg['providers']
        # filter impossible providers from possible previous version of remote server
        possible_service_types = utils.get_service_types_for_version(cls.version)
        cls.test_services_info = dict()
        for svc_name in provider_services_info:
            if provider_services_info[svc_name]['type'] in possible_service_types:
                cls.test_services_info[svc_name] = provider_services_info[svc_name]

        cls.test_service_name = u'project-api'
        cls.test_service_type = cls.test_services_info[cls.test_service_name]['type']
        utils.check_val_is_in(cls.test_service_type, cls.test_services_info)

        resp = utils.test_request(cls.url, 'GET', '/services/project-api',
                                  headers=cls.json_headers, cookies=cls.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        cls.test_service_resource_id = json_body[cls.test_service_name]['resource_id']

        cls.test_resource_name = u'magpie-unittest-resource'
        test_service_resource_types = service_type_dict[cls.test_service_type].resource_types_permissions.keys()
        assert len(test_service_resource_types), "test service should allow at least 1 sub-resource for test execution"
        cls.test_resource_type = test_service_resource_types[0]

        cls.test_user_name = u'magpie-unittest-toto'
        cls.test_user_group = u'users'

    def setUp(self):
        self.check_requirements()
        utils.TestSetup.delete_TestServiceResource(self)
        utils.TestSetup.delete_TestUser(self)

    @pytest.mark.login
    @unittest.skipUnless(runner.MAGPIE_TEST_LOGIN, reason="Skip 'login' tests requested.")
    def test_GetSession_Administrator(self):
        resp = utils.test_request(self.url, 'GET', '/session', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
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
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUsers(self):
        resp = utils.test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in('user_names', json_body)
        utils.check_val_type(json_body['user_names'], list)
        utils.check_val_equal(len(json_body['user_names']) > 1, True)     # should have more than only 'anonymous'
        utils.check_val_is_in('anonymous', json_body['user_names'])       # anonymous always in users
        utils.check_val_is_in(self.usr, json_body['user_names'])          # current test user in users

    @pytest.mark.users
    @pytest.mark.defaults
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    @unittest.skipUnless(runner.MAGPIE_TEST_DEFAULTS, reason="Skip 'defaults' tests requested.")
    def test_ValidateDefaultUsers(self):
        resp = utils.test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        users = json_body['user_names']
        utils.check_val_is_in(get_constant('MAGPIE_ANONYMOUS_USER'), users)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_USER'), users)

    @classmethod
    def check_GetUserResourcesPermissions(cls, user_name):
        route = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=cls.test_service_resource_id, usr=user_name)
        resp = utils.test_request(cls.url, 'GET', route, headers=cls.json_headers, cookies=cls.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in('permission_names', json_body)
        utils.check_val_type(json_body['permission_names'], list)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUserResourcesPermissions(self):
        self.check_GetUserResourcesPermissions(get_constant('MAGPIE_LOGGED_USER'))

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUserResourcesPermissions(self):
        self.check_GetUserResourcesPermissions(self.usr)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUserGroups(self):
        resp = utils.test_request(self.url, 'GET', '/users/current/groups',
                                  headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in('group_names', json_body)
        utils.check_val_type(json_body['group_names'], list)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_GROUP'), json_body['group_names'])

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUserInheritedResources(self):
        route = '/users/{usr}/inherited_resources'.format(usr=self.usr)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
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
                utils.check_val_type(svc_dict['resources'], dict)

    @pytest.mark.users
    @pytest.mark.defaults
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    @unittest.skipUnless(runner.MAGPIE_TEST_DEFAULTS, reason="Skip 'defaults' tests requested.")
    def test_ValidateDefaultGroups(self):
        resp = utils.test_request(self.url, 'GET', '/groups', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        groups = json_body['group_names']
        utils.check_val_is_in(get_constant('MAGPIE_ANONYMOUS_GROUP'), groups)
        utils.check_val_is_in(get_constant('MAGPIE_USERS_GROUP'), groups)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_GROUP'), groups)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
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
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUser_existing(self):
        utils.TestSetup.create_TestUser(self)

        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
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
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUser_missing(self):
        utils.TestSetup.check_NonExistingTestUser(self)
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 404)

    @pytest.mark.users
    @unittest.skipUnless(runner.MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUser(self):
        utils.TestSetup.check_NonExistingTestUser(self)
        resp = utils.test_request(self.url, 'GET', '/users/current', headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            utils.check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            utils.check_val_equal(json_body['user_name'], self.usr)

    @pytest.mark.groups
    @unittest.skipUnless(runner.MAGPIE_TEST_GROUPS, reason="Skip 'groups' tests requested.")
    def test_GetGroupUsers(self):
        route = '/groups/{grp}/users'.format(grp=get_constant('MAGPIE_ADMIN_GROUP'))
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in('user_names', json_body)
        utils.check_val_type(json_body['user_names'], list)
        utils.check_val_is_in(get_constant('MAGPIE_ADMIN_USER'), json_body['user_names'])
        utils.check_val_is_in(self.usr, json_body['user_names'])

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_GetServiceResources(self):
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
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

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_GetServicePermissions(self):
        services_list = utils.TestSetup.get_RegisteredServicesList(self)

        for svc in services_list:
            svc_name = svc['service_name']
            service_perms = service_type_dict[svc['service_type']].permission_names
            route = '/services/{svc}/permissions'.format(svc=svc_name)
            resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
            json_body = utils.check_response_basic_info(resp, 200)
            utils.check_val_is_in('permission_names', json_body)
            utils.check_val_type(json_body['permission_names'], list)
            utils.check_all_equal(json_body['permission_names'], service_perms)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_DirectResource_NoParentID(self):
        resources_prior = utils.TestSetup.get_ExistingTestServiceDirectResources(self)
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        json_body = utils.TestSetup.create_TestServiceResource(self)
        utils.check_val_is_in('resource_id', json_body)
        utils.check_val_is_in('resource_name', json_body)
        utils.check_val_is_in('resource_type', json_body)
        utils.check_val_not_in(json_body['resource_id'], resources_prior_ids)
        utils.check_val_equal(json_body['resource_name'], self.test_resource_name)
        utils.check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_DirectResource_WithParentID(self):
        resources_prior = utils.TestSetup.get_ExistingTestServiceDirectResources(self)
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        service_id = utils.TestSetup.get_ExistingTestServiceInfo(self)['resource_id']
        extra_data = {"parent_id": service_id}
        json_body = utils.TestSetup.create_TestServiceResource(self, extra_data)
        utils.check_val_is_in('resource_id', json_body)
        utils.check_val_is_in('resource_name', json_body)
        utils.check_val_is_in('resource_type', json_body)
        utils.check_val_not_in(json_body['resource_id'], resources_prior_ids)
        utils.check_val_equal(json_body['resource_name'], self.test_resource_name)
        utils.check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_ChildrenResource_ParentID(self):
        # create the direct resource
        json_body = utils.TestSetup.create_TestServiceResource(self)
        resources = utils.TestSetup.get_ExistingTestServiceDirectResources(self)
        resources_ids = [res['resource_id'] for res in resources]
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
        json_body = utils.check_response_basic_info(resp, 200)
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
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_DirectResource_Conflict(self):
        utils.TestSetup.create_TestServiceResource(self)
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        data = {"resource_name": self.test_resource_name, "resource_type": self.test_resource_type}
        resp = utils.test_request(self.url, 'POST', route, headers=self.json_headers, cookies=self.cookies, json=data)
        json_body = utils.check_response_basic_info(resp, 409)
        utils.check_error_param_structure(json_body, version=self.version,
                                          isParamValueLiteralUnicode=True, paramCompareExists=True,
                                          paramValue=self.test_resource_name, paramName=u'resource_name')

    @pytest.mark.services
    @pytest.mark.defaults
    @unittest.skipUnless(runner.MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    @unittest.skipUnless(runner.MAGPIE_TEST_DEFAULTS, reason="Skip 'defaults' tests requested.")
    def test_ValidateDefaultServiceProviders(self):
        services_list = utils.TestSetup.get_RegisteredServicesList(self)

        # ensure that registered services information are all matching the providers in config file
        # ignore registered services not from providers as their are not explicitly required from the config
        for svc in services_list:
            svc_name = svc['service_name']
            if svc_name in self.test_services_info:
                utils.check_val_equal(svc['service_type'], self.test_services_info[svc_name]['type'])
                hostname = urlparse(self.url).hostname
                twitcher_svc_url = get_twitcher_protected_service_url(svc_name, hostname=hostname)
                utils.check_val_equal(svc['public_url'], twitcher_svc_url)
                svc_url = self.test_services_info[svc_name]['url'].replace('${HOSTNAME}', hostname)
                utils.check_val_equal(svc['service_url'], svc_url)

        # ensure that no providers are missing from registered services
        registered_svc_names = [svc['service_name'] for svc in services_list]
        for svc_name in self.test_services_info:
            utils.check_val_is_in(svc_name, registered_svc_names)

        # ensure that 'getcapabilities' permission is given to anonymous for applicable services
        services_list_getcap = [svc for svc in services_list if 'getcapabilities' in svc['permission_names']]
        route = '/users/{usr}/services'.format(usr=get_constant('MAGPIE_ANONYMOUS_USER'))
        resp = utils.test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = utils.check_response_basic_info(resp, 200)
        services_body = json_body['services']
        for svc in services_list_getcap:
            svc_name = svc['service_name']
            svc_type = svc['service_type']
            anonymous = get_constant('MAGPIE_ANONYMOUS_USER')
            msg = "Service `{name}` of type `{type}` is expected to have `{perm}` permissions for user `{usr}`" \
                  .format(name=svc_name, type=svc_type, perm='getcapabilities', usr=anonymous)
            utils.check_val_is_in(svc_name, services_body[svc_type], msg=msg)
            utils.check_val_is_in('getcapabilities', services_body[svc_type][svc_name]['permission_names'])

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_PostResources_DirectServiceResource(self):
        service_info = utils.TestSetup.get_ExistingTestServiceInfo(self)
        service_resource_id = service_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_resource_id
        }
        resp = utils.test_request(self.url, 'POST', '/resources',
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = utils.check_response_basic_info(resp, 201)
        utils.check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type, self.version)

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_PostResources_ChildrenResource(self):
        resource_info = utils.TestSetup.create_TestServiceResource(self)
        direct_resource_id = resource_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": direct_resource_id
        }
        resp = utils.test_request(self.url, 'POST', '/resources',
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = utils.check_response_basic_info(resp, 201)
        utils.check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type, self.version)

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_PostResources_MissingParentID(self):
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = utils.test_request(self.url, 'POST', '/resources',
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = utils.check_response_basic_info(resp, 422)
        utils.check_error_param_structure(json_body, paramName='parent_id', paramValue=repr(None), version=self.version)

    @pytest.mark.resources
    @unittest.skipUnless(runner.MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_DeleteResource(self):
        json_body = utils.TestSetup.create_TestServiceResource(self)
        resource_id = json_body['resource_id']

        route = '/resources/{res_id}'.format(res_id=resource_id)
        resp = utils.test_request(self.url, 'DELETE', route, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200)
        utils.TestSetup.check_NonExistingTestResource(self)


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
