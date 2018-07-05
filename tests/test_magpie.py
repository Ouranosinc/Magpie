#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie
----------------------------------

Tests for `magpie` module.
"""

import unittest
import pytest
import pyramid.testing
from magpie import magpie
from test_utils import *


@pytest.mark.offline
class TestMagpieNoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    def test_Home_valid(self):
        resp = test_request(self.app, 'GET', '/', headers=json_headers)
        assert resp.status_code == 200
        assert resp.content_type == 'text/html'
        resp.mustcontain("Magpie Administration")

    @pytest.mark.login
    def test_GetSession_Anonymous_valid(self):
        resp = test_request(self.app, 'GET', '/session', headers=json_headers)
        check_response_basic_info(resp, 200)
        assert resp.json['authenticated'] is False
        assert 'group_names' not in resp.json

    def test_GetVersion_valid(self):
        resp = test_request(self.app, 'GET', '/version', headers=json_headers)
        check_response_basic_info(resp, 200)
        assert resp.json['version'] == magpie.__meta__.__version__


@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.offline
class TestMagpieWithUsersAuthLocal(unittest.TestCase):
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
class TestMagpieWithAdminAuthLocal(unittest.TestCase):
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
        cls.require = "cannot run tests without logged in 'administrator' user"
        assert cls.headers and cls.cookies, cls.require
        cls.app.cookies = cls.cookies
        cls.json_headers = cls.headers + json_headers

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
        assert resp.json['version'] == magpie.__meta__.__version__

    @pytest.mark.user
    def test_GetUsers_valid(self):
        resp = test_request(self.app, 'GET', '/users', headers=self.json_headers)
        check_response_basic_info(resp, 200)
        assert 'user_names' in resp.json.keys()
        assert len(resp.json['user_names']) > 1         # should have more than only 'anonymous'
        assert 'anonymous' in resp.json['user_names']   # anonymous always in users


@pytest.mark.online
class TestMagpieNoAuthRemote(unittest.TestCase):
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

    def test_Home_valid(self):
        resp = test_request(self.url, 'GET', '/', headers=json_headers)
        assert resp.status_code == 200
        assert resp.content_type == 'text/html'
        resp.mustcontain("Magpie Administration")

    @pytest.mark.login
    def test_GetSession_Anonymous_valid(self):
        resp = test_request(self.app, 'GET', '/session', headers=json_headers)
        check_response_basic_info(resp, 200)
        assert resp.json['authenticated'] is False
        assert 'group_names' not in resp.json

    def test_GetVersion_valid(self):
        resp = test_request(self.app, 'GET', '/version', headers=json_headers)
        check_response_basic_info(resp, 200)
        assert resp.json['version'] == magpie.__meta__.__version__


@pytest.mark.online
class TestMagpieWithAdminAuthRemote(unittest.TestCase):
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
        cls.require = "cannot run tests without logged in 'administrator' user"
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
        resp = test_request(cls.url, 'GET', '/services/project-api', headers=cls.json_headers, cookies=cls.cookies)
        check_response_basic_info(resp, 200)
        cls.test_resource_id = resp.json()['project-api']['resource_id']

    def setUp(self):
        self.check_requirements()

    @pytest.mark.login
    def test_GetSession_Administrator_valid(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert json_body['authenticated'] is True
        assert json_body['user_name'] == self.usr
        assert 'administrators' in json_body['group_names']
        assert 'user_email' in json_body

    @pytest.mark.user
    def test_GetUsers_valid(self):
        resp = test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'user_names' in json_body
        assert len(json_body['user_names']) > 1         # should have more than only 'anonymous'
        assert 'anonymous' in json_body['user_names']   # anonymous always in users
        assert self.usr in json_body['user_names']      # current test user in users

    @pytest.mark.user
    def test_GetCurrentUserResourcesPermissions_valid(self):
        route = '/users/current/resources/{res_id}/permissions'.format(res_id=self.test_resource_id)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        json_body = resp.json()
        assert 'permission_names' in json_body
        assert type(json_body['permission_names']) is list


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
