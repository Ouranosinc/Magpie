#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_api
----------------------------------

Tests for `magpie.api` module.
"""

import os
import unittest
import pytest
import pyramid.testing
import yaml
import six
from six.moves.urllib.parse import urlparse
from magpie.services import service_type_dict
from magpie.register import get_twitcher_protected_service_url
from magpie.api.api_rest_schemas import SwaggerGenerator
from magpie import __meta__, constants
from tests.utils import *
from tests.runner import *


@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieAPI_NoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = get_headers_content_type(cls.app, 'application/json')
        cls.version = __meta__.__version__
        cls.cookies = None
        cls.usr = constants.ANONYMOUS_USER

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    @unittest.skipUnless(MAGPIE_TEST_LOGIN, reason="Skip 'login' tests requested.")
    def test_GetSession_Anonymous(self):
        resp = test_request(self.app, 'GET', '/session', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_equal(json_body['authenticated'], False)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_not_in('user', json_body)
        else:
            check_val_not_in('user_name', json_body)
            check_val_not_in('user_email', json_body)
            check_val_not_in('group_names', json_body)

    def test_GetVersion(self):
        resp = test_request(self.app, 'GET', '/version', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('db_version', json_body)
        check_val_is_in('version', json_body)
        check_val_equal(json_body['version'], self.version)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUser(self):
        resp = test_request(self.url, 'GET', '/users/{}'.format(constants.LOGGED_USER), headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            check_val_equal(json_body['user_name'], self.usr)


@unittest.skip("Not implemented.")
@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieAPI_UsersAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Users' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()


@unittest.skip("Signin not working, cannot test protected paths.")
@pytest.mark.skip(reason="Signin not working, cannot test protected paths.")
@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieAPI_AdminAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.usr = os.getenv('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = os.getenv('MAGPIE_TEST_ADMIN_PASSWORD')
        assert cls.usr and cls.pwd, "cannot login with unspecified username/password"
        cls.headers, cls.cookies = check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(constants.ADMIN_GROUP)
        cls.json_headers = get_headers_content_type(cls.app, 'application/json')
        assert cls.headers and cls.cookies, cls.require
        cls.app.cookies = cls.cookies
        cls.version = TestSetup.get_Version(cls)

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies and cls.app.cookies, cls.require

    def setUp(self):
        self.check_requirements()

    def test_GetAPI(self):
        resp = test_request(self.app, 'GET', SwaggerGenerator.path, headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('db_version', json_body)
        check_val_is_in('version', json_body)
        check_val_equal(json_body['version'], __meta__.__version__)
        check_val_type(json_body['version'], six.string_types)
        version_parts = json_body['version'].split('.')
        check_val_equal(len(version_parts), 3)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUsers(self):
        resp = test_request(self.app, 'GET', '/users', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('user_names', json_body)
        check_val_is_in('anonymous', json_body['user_names'])       # anonymous always in users
        check_val_equal(len(json_body['user_names']) > 1, True)     # should have more than only 'anonymous'


@pytest.mark.api
@pytest.mark.remote
@unittest.skipUnless(MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(MAGPIE_TEST_REMOTE, reason="Skip 'remote' tests requested.")
class TestMagpieAPI_NoAuthRemote(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        assert cls.url, "cannot test without a remote server URL"
        cls.json_headers = get_headers_content_type(cls.url, 'application/json')
        cls.cookies = None
        cls.usr = constants.ANONYMOUS_USER
        cls.version = TestSetup.get_Version(cls)

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    @unittest.skipUnless(MAGPIE_TEST_LOGIN, reason="Skip 'login' tests requested.")
    def test_GetSession_Anonymous(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_equal(json_body['authenticated'], False)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_not_in('user', json_body)
        else:
            check_val_not_in('user_name', json_body)
            check_val_not_in('user_email', json_body)
            check_val_not_in('group_names', json_body)

    def test_GetVersion(self):
        resp = test_request(self.url, 'GET', '/version', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('db_version', json_body)
        check_val_is_in('version', json_body)
        # server not necessarily at latest version, ensure at least format
        #check_val_equal(json_body['version'], magpie.__meta__.__version__)
        check_val_type(json_body['version'], six.string_types)
        version_parts = json_body['version'].split('.')
        check_val_equal(len(version_parts), 3)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUser(self):
        resp = test_request(self.url, 'GET', '/users/current', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            check_val_equal(json_body['user_name'], self.usr)


@pytest.mark.api
@pytest.mark.remote
@unittest.skipUnless(MAGPIE_TEST_API, reason="Skip 'api' tests requested.")
@unittest.skipUnless(MAGPIE_TEST_REMOTE, reason="Skip 'remote' tests requested.")
class TestMagpieAPI_AdminAuthRemote(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.usr = os.getenv('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = os.getenv('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        assert cls.url, "cannot test without a remote server URL"
        assert cls.usr and cls.pwd, "cannot login with unspecified username/password"
        cls.headers, cls.cookies = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(constants.ADMIN_GROUP)
        cls.json_headers = get_headers_content_type(cls.url, 'application/json')
        cls.check_requirements()
        cls.version = TestSetup.get_Version(cls)
        cls.get_test_values()

    @classmethod
    def tearDownClass(cls):
        TestSetup.delete_TestServiceResource(cls)
        TestSetup.delete_TestUser(cls)
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    @classmethod
    def get_test_values(cls):
        services_cfg = yaml.load(open(constants.MAGPIE_PROVIDERS_CONFIG_PATH, 'r'))
        provider_services_info = services_cfg['providers']
        # filter impossible providers from possible previous version of remote server
        possible_service_types = get_service_types_for_version(cls.version)
        cls.test_services_info = dict()
        for svc_name in provider_services_info:
            if provider_services_info[svc_name]['type'] in possible_service_types:
                cls.test_services_info[svc_name] = provider_services_info[svc_name]

        cls.test_service_name = u'project-api'
        cls.test_service_type = cls.test_services_info[cls.test_service_name]['type']
        check_val_is_in(cls.test_service_type, cls.test_services_info)

        resp = test_request(cls.url, 'GET', '/services/project-api', headers=cls.json_headers, cookies=cls.cookies)
        json_body = check_response_basic_info(resp, 200)
        cls.test_service_resource_id = json_body[cls.test_service_name]['resource_id']

        cls.test_resource_name = u'magpie-unittest-resource'
        test_service_resource_types = service_type_dict[cls.test_service_type].resource_types_permissions.keys()
        assert len(test_service_resource_types), "test service should allow at least 1 sub-resource for test execution"
        cls.test_resource_type = test_service_resource_types[0]

        cls.test_user_name = u'magpie-unittest-toto'
        cls.test_user_group = u'users'

    def setUp(self):
        self.check_requirements()
        TestSetup.delete_TestServiceResource(self)
        TestSetup.delete_TestUser(self)

    @pytest.mark.login
    @unittest.skipUnless(MAGPIE_TEST_LOGIN, reason="Skip 'login' tests requested.")
    def test_GetSession_Administrator(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_equal(json_body['authenticated'], True)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_is_in('user', json_body)
            check_val_equal(json_body['user']['user_name'], self.usr)
            check_val_is_in(constants.ADMIN_GROUP, json_body['user']['group_names'])
            check_val_type(json_body['user']['group_names'], list)
            check_val_is_in('email', json_body['user'])
        else:
            check_val_equal(json_body['user_name'], self.usr)
            check_val_is_in(constants.ADMIN_GROUP, json_body['group_names'])
            check_val_type(json_body['group_names'], list)
            check_val_is_in('user_email', json_body)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUsers(self):
        resp = test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('user_names', json_body)
        check_val_type(json_body['user_names'], list)
        check_val_equal(len(json_body['user_names']) > 1, True)     # should have more than only 'anonymous'
        check_val_is_in('anonymous', json_body['user_names'])       # anonymous always in users
        check_val_is_in(self.usr, json_body['user_names'])          # current test user in users

    @pytest.mark.users
    @pytest.mark.defaults
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    @unittest.skipUnless(MAGPIE_TEST_DEFAULTS, reason="Skip 'defaults' tests requested.")
    def test_ValidateDefaultUsers(self):
        resp = test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        users = json_body['user_names']
        check_val_is_in(constants.ANONYMOUS_USER, users)
        check_val_is_in(constants.ADMIN_USER, users)

    @classmethod
    def check_GetUserResourcesPermissions(cls, user_name):
        route = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=cls.test_service_resource_id, usr=user_name)
        resp = test_request(cls.url, 'GET', route, headers=cls.json_headers, cookies=cls.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('permission_names', json_body)
        check_val_type(json_body['permission_names'], list)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUserResourcesPermissions(self):
        self.check_GetUserResourcesPermissions(constants.LOGGED_USER)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUserResourcesPermissions(self):
        self.check_GetUserResourcesPermissions(self.usr)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUserGroups(self):
        resp = test_request(self.url, 'GET', '/users/current/groups', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('group_names', json_body)
        check_val_type(json_body['group_names'], list)
        check_val_is_in(constants.ADMIN_GROUP, json_body['group_names'])

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUserInheritedResources(self):
        route = '/users/{usr}/inherited_resources'.format(usr=self.usr)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('resources', json_body)
        check_val_type(json_body['resources'], dict)
        check_all_equal(json_body['resources'].keys(), get_service_types_for_version(self.version), any_order=True)
        for svc_type in json_body['resources']:
            for svc in json_body['resources'][svc_type]:
                svc_dict = json_body['resources'][svc_type][svc]
                check_val_type(svc_dict, dict)
                check_val_is_in('resource_id', svc_dict)
                check_val_is_in('service_name', svc_dict)
                check_val_is_in('service_type', svc_dict)
                check_val_is_in('service_url', svc_dict)
                check_val_is_in('public_url', svc_dict)
                check_val_is_in('permission_names', svc_dict)
                check_val_is_in('resources', svc_dict)
                check_val_type(svc_dict['resource_id'], int)
                check_val_type(svc_dict['service_name'], six.string_types)
                check_val_type(svc_dict['service_url'], six.string_types)
                check_val_type(svc_dict['service_type'], six.string_types)
                check_val_type(svc_dict['public_url'], six.string_types)
                check_val_type(svc_dict['permission_names'], list)
                check_val_type(svc_dict['resources'], dict)

    @pytest.mark.users
    @pytest.mark.defaults
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    @unittest.skipUnless(MAGPIE_TEST_DEFAULTS, reason="Skip 'defaults' tests requested.")
    def test_ValidateDefaultGroups(self):
        resp = test_request(self.url, 'GET', '/groups', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        groups = json_body['group_names']
        check_val_is_in(constants.ANONYMOUS_GROUP, groups)
        check_val_is_in(constants.USERS_GROUP, groups)
        check_val_is_in(constants.ADMIN_GROUP, groups)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_PostUsers(self):
        json_body = TestSetup.create_TestUser(self)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_is_in('user', json_body)
            check_val_is_in('user_name', json_body['user'])
            check_val_type(json_body['user']['user_name'], six.string_types)
            check_val_is_in('email', json_body['user'])
            check_val_type(json_body['user']['email'], six.string_types)
            check_val_is_in('group_names', json_body['user'])
            check_val_type(json_body['user']['group_names'], list)

        users = TestSetup.get_RegisteredUsersList(self)
        check_val_is_in(self.test_user_name, users)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUser_existing(self):
        TestSetup.create_TestUser(self)

        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_is_in('user', json_body)
            check_val_is_in('user_name', json_body['user'])
            check_val_type(json_body['user']['user_name'], six.string_types)
            check_val_is_in('email', json_body['user'])
            check_val_type(json_body['user']['email'], six.string_types)
            check_val_is_in('group_names', json_body['user'])
            check_val_type(json_body['user']['group_names'], list)
        else:
            check_val_is_in('user_name', json_body)
            check_val_type(json_body['user_name'], six.string_types)
            check_val_is_in('email', json_body)
            check_val_type(json_body['email'], six.string_types)
            check_val_is_in('group_names', json_body)
            check_val_type(json_body['group_names'], list)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetUser_missing(self):
        TestSetup.check_NonExistingTestUser(self)
        route = '/users/{usr}'.format(usr=self.test_user_name)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 404)

    @pytest.mark.users
    @unittest.skipUnless(MAGPIE_TEST_USERS, reason="Skip 'users' tests requested.")
    def test_GetCurrentUser(self):
        TestSetup.check_NonExistingTestUser(self)
        resp = test_request(self.url, 'GET', '/users/current', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        if LooseVersion(self.version) >= LooseVersion('0.6.3'):
            check_val_equal(json_body['user']['user_name'], self.usr)
        else:
            check_val_equal(json_body['user_name'], self.usr)

    @pytest.mark.groups
    @unittest.skipUnless(MAGPIE_TEST_GROUPS, reason="Skip 'groups' tests requested.")
    def test_GetGroupUsers(self):
        route = '/groups/{grp}/users'.format(grp=constants.ADMIN_GROUP)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('user_names', json_body)
        check_val_type(json_body['user_names'], list)
        check_val_is_in(constants.ADMIN_USER, json_body['user_names'])
        check_val_is_in(self.usr, json_body['user_names'])

    @pytest.mark.services
    @unittest.skipUnless(MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_GetServiceResources(self):
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        svc_dict = json_body[self.test_service_name]
        check_val_is_in(self.test_service_name, json_body)
        check_val_type(json_body[self.test_service_name], dict)
        check_val_is_in('resource_id', svc_dict)
        check_val_is_in('service_name', svc_dict)
        check_val_is_in('service_type', svc_dict)
        check_val_is_in('service_url', svc_dict)
        check_val_is_in('public_url', svc_dict)
        check_val_is_in('permission_names', svc_dict)
        check_val_is_in('resources', svc_dict)
        check_val_type(svc_dict['resource_id'], int)
        check_val_type(svc_dict['service_name'], six.string_types)
        check_val_type(svc_dict['service_url'], six.string_types)
        check_val_type(svc_dict['service_type'], six.string_types)
        check_val_type(svc_dict['public_url'], six.string_types)
        check_val_type(svc_dict['permission_names'], list)
        check_resource_children(svc_dict['resources'], svc_dict['resource_id'], svc_dict['resource_id'])

    @pytest.mark.services
    @unittest.skipUnless(MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_GetServicePermissions(self):
        services_list = TestSetup.get_RegisteredServicesList(self)

        for svc in services_list:
            svc_name = svc['service_name']
            service_perms = service_type_dict[svc['service_type']].permission_names
            route = '/services/{svc}/permissions'.format(svc=svc_name)
            resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
            json_body = check_response_basic_info(resp, 200)
            check_val_is_in('permission_names', json_body)
            check_val_type(json_body['permission_names'], list)
            check_all_equal(json_body['permission_names'], service_perms)

    @pytest.mark.services
    @unittest.skipUnless(MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_DirectResource_NoParentID(self):
        resources_prior = TestSetup.get_ExistingTestServiceDirectResources(self)
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        json_body = TestSetup.create_TestServiceResource(self)
        check_val_is_in('resource_id', json_body)
        check_val_is_in('resource_name', json_body)
        check_val_is_in('resource_type', json_body)
        check_val_not_in(json_body['resource_id'], resources_prior_ids)
        check_val_equal(json_body['resource_name'], self.test_resource_name)
        check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    @unittest.skipUnless(MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_DirectResource_WithParentID(self):
        resources_prior = TestSetup.get_ExistingTestServiceDirectResources(self)
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        service_id = TestSetup.get_ExistingTestServiceInfo(self)['resource_id']
        extra_data = {"parent_id": service_id}
        json_body = TestSetup.create_TestServiceResource(self, extra_data)
        check_val_is_in('resource_id', json_body)
        check_val_is_in('resource_name', json_body)
        check_val_is_in('resource_type', json_body)
        check_val_not_in(json_body['resource_id'], resources_prior_ids)
        check_val_equal(json_body['resource_name'], self.test_resource_name)
        check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    @unittest.skipUnless(MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_ChildrenResource_ParentID(self):
        # create the direct resource
        json_body = TestSetup.create_TestServiceResource(self)
        resources = TestSetup.get_ExistingTestServiceDirectResources(self)
        resources_ids = [res['resource_id'] for res in resources]
        test_resource_id = json_body['resource_id']
        check_val_is_in(test_resource_id, resources_ids, msg="service resource must exist to create children resource")

        # create the children resource under the direct resource and validate response info
        child_resource_name = self.test_resource_name + "-children"
        data_override = {
            "resource_name": child_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": test_resource_id
        }
        json_body = TestSetup.create_TestServiceResource(self, data_override)
        check_val_is_in('resource_id', json_body)
        check_val_not_in(json_body['resource_id'], resources_ids)
        check_val_is_in('resource_name', json_body)
        check_val_equal(json_body['resource_name'], child_resource_name)
        check_val_is_in('resource_type', json_body)
        check_val_equal(json_body['resource_type'], self.test_resource_type)

        # validate created children resource info
        service_root_id = TestSetup.get_ExistingTestServiceInfo(self)['resource_id']
        child_resource_id = json_body['resource_id']
        route = '/resources/{res_id}'.format(res_id=child_resource_id)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in(str(child_resource_id), json_body)
        resource_body = json_body[str(child_resource_id)]
        check_val_equal(resource_body['root_service_id'], service_root_id)
        check_val_equal(resource_body['parent_id'], test_resource_id)
        check_val_equal(resource_body['resource_id'], child_resource_id)
        check_val_equal(resource_body['resource_name'], child_resource_name)
        check_val_equal(resource_body['resource_type'], self.test_resource_type)
        check_val_type(resource_body['children'], dict)
        check_val_equal(len(resource_body['children']), 0)

    @pytest.mark.services
    @unittest.skipUnless(MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    def test_PostServiceResources_DirectResource_Conflict(self):
        TestSetup.create_TestServiceResource(self)
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        data = {"resource_name": self.test_resource_name, "resource_type": self.test_resource_type}
        resp = test_request(self.url, 'POST', route, headers=self.json_headers, cookies=self.cookies, json=data)
        json_body = check_response_basic_info(resp, 409)
        check_error_param_structure(json_body, version=self.version,
                                    isParamValueLiteralUnicode=True, paramCompareExists=True,
                                    paramValue=self.test_resource_name, paramName=u'resource_name')

    @pytest.mark.services
    @pytest.mark.defaults
    @unittest.skipUnless(MAGPIE_TEST_SERVICES, reason="Skip 'services' tests requested.")
    @unittest.skipUnless(MAGPIE_TEST_DEFAULTS, reason="Skip 'defaults' tests requested.")
    def test_ValidateDefaultServiceProviders(self):
        services_list = TestSetup.get_RegisteredServicesList(self)

        # ensure that registered services information are all matching the providers in config file
        # ignore registered services not from providers as their are not explicitly required from the config
        for svc in services_list:
            svc_name = svc['service_name']
            if svc_name in self.test_services_info:
                check_val_equal(svc['service_type'], self.test_services_info[svc_name]['type'])
                hostname = urlparse(self.url).hostname
                check_val_equal(svc['public_url'], get_twitcher_protected_service_url(svc_name, hostname=hostname))
                svc_url = self.test_services_info[svc_name]['url'].replace('${HOSTNAME}', hostname)
                check_val_equal(svc['service_url'], svc_url)

        # ensure that no providers are missing from registered services
        registered_svc_names = [svc['service_name'] for svc in services_list]
        for svc_name in self.test_services_info:
            check_val_is_in(svc_name, registered_svc_names)

        # ensure that 'getcapabilities' permission is given to anonymous for applicable services
        services_list_getcap = [svc for svc in services_list if 'getcapabilities' in svc['permission_names']]
        route = '/users/{usr}/services'.format(usr=constants.ANONYMOUS_USER)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        services_body = json_body['services']
        for svc in services_list_getcap:
            svc_name = svc['service_name']
            svc_type = svc['service_type']
            msg = "Service `{name}` of type `{type}` is expected to have `{perm}` permissions for user `{usr}`" \
                  .format(name=svc_name, type=svc_type, perm='getcapabilities', usr=constants.ANONYMOUS_USER)
            check_val_is_in(svc_name, services_body[svc_type], msg=msg)
            check_val_is_in('getcapabilities', services_body[svc_type][svc_name]['permission_names'])

    @pytest.mark.resources
    @unittest.skipUnless(MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_PostResources_DirectServiceResource(self):
        service_info = TestSetup.get_ExistingTestServiceInfo(self)
        service_resource_id = service_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_resource_id
        }
        resp = test_request(self.url, 'POST', '/resources', headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = check_response_basic_info(resp, 201)
        check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type, self.version)

    @pytest.mark.resources
    @unittest.skipUnless(MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_PostResources_ChildrenResource(self):
        resource_info = TestSetup.create_TestServiceResource(self)
        direct_resource_id = resource_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": direct_resource_id
        }
        resp = test_request(self.url, 'POST', '/resources', headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = check_response_basic_info(resp, 201)
        check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type, self.version)

    @pytest.mark.resources
    @unittest.skipUnless(MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_PostResources_MissingParentID(self):
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = test_request(self.url, 'POST', '/resources', headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = check_response_basic_info(resp, 422)
        check_error_param_structure(json_body, paramName='parent_id', paramValue=repr(None), version=self.version)

    @pytest.mark.resources
    @unittest.skipUnless(MAGPIE_TEST_RESOURCES, reason="Skip 'resources' tests requested.")
    def test_DeleteResource(self):
        json_body = TestSetup.create_TestServiceResource(self)
        resource_id = json_body['resource_id']

        route = '/resources/{res_id}'.format(res_id=resource_id)
        resp = test_request(self.url, 'DELETE', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        TestSetup.check_NonExistingTestResource(self)


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
