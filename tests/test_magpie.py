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


@pytest.mark.online
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
        resp = self.app.get('/', headers=json_headers)
        assert resp.status_int == 200
        assert resp.content_type == 'text/html'
        resp.mustcontain("Magpie Administration")

    def test_GetVersion_valid(self):
        resp = self.app.get('/version', headers=json_headers)
        assert resp.status_int == 200
        assert resp.content_type == 'application/json'
        assert resp.json['version'] == magpie.__meta__.__version__


@pytest.mark.online
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


@pytest.mark.online
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

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()


    #@pytest.mark.skip(reason='No way to test this now')
    def test_GetAPI_valid(self):
        assert check_or_try_login_user(self.app, self.usr, self.pwd) is not None, self.require
        assert self.headers is not None, self.require
        resp = self.app.get('/__api__', headers=json_headers + self.headers)
        assert resp.status_int == 200
        assert resp.content_type == 'application/json'
        assert resp.json['version'] == magpie.__meta__.__version__


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
