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
class TestMagpieNoAuth(unittest.TestCase):
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

    def test_GetVersion_valid(self):
        resp = test_request(self.app, 'GET', '/version', headers=json_headers)
        assert resp.status_code == 200
        assert resp.content_type == 'application/json'
        assert resp.json['version'] == magpie.__meta__.__version__


@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.offline
class TestMagpieWithUsersAuth(unittest.TestCase):
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
class TestMagpieWithAdminAuth(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.usr = os.getenv('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = os.getenv('MAGPIE_TEST_ADMIN_PASSWORD')
        assert cls.usr is not None and cls.pwd is not None, "cannot login with unspecified username/password"
        cls.headers = check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in 'administrator' user"
        assert cls.headers is not None, cls.require
        cls.json_headers = cls.headers + json_headers

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        assert check_or_try_login_user(cls.app, cls.usr, cls.pwd) is not None, cls.require
        assert cls.headers is not None, cls.require

    #@pytest.mark.skip(reason='No way to test this now')
    def test_GetAPI_valid(self):
        self.check_requirements()
        resp = test_request(self.app, 'GET', '/__api__', headers=self.json_headers)
        assert resp.status_code == 200
        assert resp.content_type == 'application/json'
        assert resp.json['version'] == magpie.__meta__.__version__

    @pytest.mark.user
    def test_GetUsers_valid(self):
        self.check_requirements()
        resp = test_request(self.app, 'GET', '/users', headers=self.json_headers)
        assert resp.status_code == 200
        assert resp.content_type == 'application/json'
        assert 'users' in resp.json.keys()
        assert 'anonymous' in resp.json['users']
        assert len(resp.json['users']) > 1  # should have more than only 'anonymous'


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
        assert cls.url is not None, "cannot test without a remote server URL"
        assert cls.usr is not None and cls.pwd is not None, "cannot login with unspecified username/password"
        cls.headers = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in 'administrator' user"
        assert cls.headers is not None, cls.require
        cls.json_headers = dict(cls.headers)

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        assert check_or_try_login_user(cls.url, cls.usr, cls.pwd) is not None, cls.require
        assert cls.headers is not None, cls.require

    @pytest.mark.user
    def test_GetUsers_valid(self):
        self.check_requirements()
        resp = test_request(self.url, 'GET', '/users', headers=self.json_headers)
        assert resp.status_code == 200
        assert resp.content_type == 'application/json'
        assert 'users' in resp.json.keys()
        assert 'anonymous' in resp.json['users']
        assert len(resp.json['users']) > 1  # should have more than only 'anonymous'


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
