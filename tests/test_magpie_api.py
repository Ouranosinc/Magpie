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
import six
import yaml
from magpie import *
from magpie.services import service_type_dict
from magpie import magpie
from test_utils import *


@pytest.mark.offline
@pytest.mark.api
class TestMagpieAPI_NoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.json_headers = [('Content-Type', 'application/json')]

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    def test_GetSession_Anonymous_valid(self):
        resp = test_request(self.app, 'GET', '/session', headers=self.json_headers)
        check_response_basic_info(resp, 200)
        assert resp.json['authenticated'] is False
        assert 'group_names' not in resp.json

    def test_GetVersion_valid(self):
        resp = test_request(self.app, 'GET', '/version', headers=self.json_headers)
        check_response_basic_info(resp, 200)
        assert resp.json['version'] == magpie.__meta__.__version__


@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.offline
@pytest.mark.api
class TestMagpieAPI_WithUsersAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Users' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()


@pytest.mark.skip(reason="Signin not working, cannot test protected paths.")
@pytest.mark.offline
@pytest.mark.api
class TestMagpieAPI_WithAdminAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.usr = os.getenv('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = os.getenv('MAGPIE_TEST_ADMIN_PASSWORD')
        assert cls.usr and cls.pwd, "cannot login with unspecified username/password"
        cls.headers, cls.cookies = check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(ADMIN_GROUP)
        assert cls.headers and cls.cookies, cls.require
        cls.app.cookies = cls.cookies
        cls.json_headers = [('Content-Type', 'application/json')]

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

    def test_GetAPI_valid(self):
        resp = test_request(self.app, 'GET', '/__api__', headers=self.json_headers)
        check_response_basic_info(resp, 200)
        assert 'db_version' in resp.json
        assert 'version' in resp.json
        assert resp.json['version'] == magpie.__meta__.__version__

    @pytest.mark.users
    def test_GetUsers_valid(self):
        resp = test_request(self.app, 'GET', '/users', headers=self.json_headers)
        check_response_basic_info(resp, 200)
        assert 'user_names' in resp.json.keys()
        assert len(resp.json['user_names']) > 1         # should have more than only 'anonymous'
        assert 'anonymous' in resp.json['user_names']   # anonymous always in users


@pytest.mark.online
@pytest.mark.api
class TestMagpieAPI_NoAuthRemote(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        assert cls.url, "cannot test without a remote server URL"
        cls.json_headers = {'Content-Type': 'application/json'}

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    def test_GetSession_Anonymous_valid(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert json_body['authenticated'] is False
        assert 'group_names' not in json_body

    def test_GetVersion_valid(self):
        resp = test_request(self.url, 'GET', '/version', headers=self.json_headers)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'db_version' in json_body
        assert 'version' in json_body
        assert json_body['version'] == magpie.__meta__.__version__


@pytest.mark.online
@pytest.mark.api
class TestMagpieAPI_WithAdminAuthRemote(unittest.TestCase):
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
        cls.require = "cannot run tests without logged in '{}' user".format(ADMIN_GROUP)
        cls.json_headers = {'Content-Type': 'application/json'}
        cls.check_requirements()
        cls.get_test_values()

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    @classmethod
    def get_test_values(cls):
        services_cfg = yaml.load(open(MAGPIE_PROVIDERS_CONFIG_PATH, 'r'))
        cls.test_services_info = services_cfg['providers']
        cls.test_service_name = 'project-api'
        cls.test_service_type = cls.test_services_info[cls.test_service_name]['type']
        assert cls.test_service_type in cls.test_services_info

        resp = test_request(cls.url, 'GET', '/services/project-api', headers=cls.json_headers, cookies=cls.cookies)
        check_response_basic_info(resp, 200)
        cls.test_resource_id = resp.json()[cls.test_service_name]['resource_id']

    def setUp(self):
        self.check_requirements()

    @pytest.mark.login
    def test_GetSession_Administrator_valid(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert json_body['authenticated'] is True
        assert json_body['user_name'] == self.usr
        assert ADMIN_GROUP in json_body['group_names']
        assert 'user_email' in json_body

    @pytest.mark.users
    def test_GetUsers_valid(self):
        resp = test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'user_names' in json_body
        assert len(json_body['user_names']) > 1         # should have more than only 'anonymous'
        assert 'anonymous' in json_body['user_names']   # anonymous always in users
        assert self.usr in json_body['user_names']      # current test user in users

    @pytest.mark.users
    def test_GetCurrentUserResourcesPermissions_valid(self):
        route = '/users/current/resources/{res_id}/permissions'.format(res_id=self.test_resource_id)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'permission_names' in json_body
        assert isinstance(json_body['permission_names'], list)

    @pytest.mark.users
    def test_GetCurrentUserGroups_valid(self):
        resp = test_request(self.url, 'GET', '/users/current/groups', headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'group_names' in json_body
        assert isinstance(json_body['group_names'], list)
        assert ADMIN_GROUP in json_body['group_names']

    @pytest.mark.users
    def test_GetUserInheritedResources_valid(self):
        route = '/users/{usr}/inherited_resources'.format(usr=self.usr)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'resources' in json_body
        assert isinstance(json_body['resources'], dict)
        assert all_equal(json_body['resources'].keys(), service_type_dict.keys(), any_order=True)
        for svc_type in json_body['resources']:
            for svc in json_body['resources'][svc_type]:
                svc_dict = json_body['resources'][svc_type][svc]
                assert 'resource_id' in svc_dict
                assert isinstance(svc_dict['resource_id'], int)
                assert 'service_name' in svc_dict
                assert isinstance(svc_dict['service_name'], six.string_types)
                assert 'service_url' in svc_dict
                assert isinstance(svc_dict['service_url'], six.string_types)
                assert 'service_type' in svc_dict
                assert isinstance(svc_dict['service_type'], six.string_types)
                assert 'public_url' in svc_dict
                assert isinstance(svc_dict['public_url'], six.string_types)
                assert 'permission_names' in svc_dict
                assert isinstance(svc_dict['permission_names'], list)
                assert 'resources' in svc_dict
                assert isinstance(svc_dict['resources'], dict)

    @pytest.mark.groups
    def test_GetGroupUsers_valid(self):
        route = '/groups/{grp}/users'.format(grp=ADMIN_GROUP)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'user_names' in json_body
        assert isinstance(json_body['user_names'], list)
        assert ADMIN_USER in json_body['user_names']
        assert self.usr in json_body['user_names']

    @pytest.mark.services
    def test_GetServiceResources_valid(self):
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        svc_dict = json_body[self.test_service_name]
        assert self.test_service_name in json_body
        assert isinstance(json_body[self.test_service_name], dict)

        assert 'resource_id' in svc_dict
        assert isinstance(svc_dict['resource_id'], int)
        assert 'service_name' in svc_dict
        assert isinstance(svc_dict['service_name'], six.string_types)
        assert 'service_url' in svc_dict
        assert isinstance(svc_dict['service_url'], six.string_types)
        assert 'service_type' in svc_dict
        assert isinstance(svc_dict['service_type'], six.string_types)
        assert 'public_url' in svc_dict
        assert isinstance(svc_dict['public_url'], six.string_types)
        assert 'permission_names' in svc_dict
        assert isinstance(svc_dict['permission_names'], list)
        assert 'resources' in svc_dict
        check_resource_children(svc_dict['resources'], svc_dict['resource_id'], svc_dict['resource_id'])


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
