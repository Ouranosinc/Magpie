#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_ui
----------------------------------

Tests for `magpie.ui` module.
"""

import os
import unittest
import pytest
import pyramid.testing
import six
import yaml
import magpie
from services import service_type_dict
from magpie import *
from tests.utils import *


@pytest.mark.offline
@pytest.mark.ui
class TestMagpieUI_NoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = get_headers_content_type(cls.app, 'application/json')
        cls.cookies = None

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.status
    def test_Home(self):
        TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    def test_Login(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/login')


@unittest.skip("Not implemented.")
@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.offline
@pytest.mark.api
class TestMagpieUI_AdminAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()


@pytest.mark.online
@pytest.mark.ui
class TestMagpieUI_NoAuthRemote(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        assert cls.url, "cannot test without a remote server URL"
        cls.json_headers = get_headers_content_type(cls.url, 'application/json')
        cls.cookies = None
        cls.usr = magpie.ANONYMOUS_USER
        cls.version = TestSetup.get_Version(cls)

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.status
    def test_Home(self):
        TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    def test_Login(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/login')


@pytest.mark.online
@pytest.mark.ui
class TestMagpieUI_AdminAuthRemote(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.usr = os.getenv('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = os.getenv('MAGPIE_TEST_ADMIN_PASSWORD')
        assert cls.url, "cannot test without a remote server URL"
        assert cls.usr and cls.pwd, "cannot login with unspecified username/password"
        cls.headers, cls.cookies = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(magpie.ADMIN_GROUP)
        cls.json_headers = get_headers_content_type(cls.url, 'application/json')
        cls.check_requirements()
        cls.version = TestSetup.get_Version(cls)
        cls.test_service_type = service_type_dict.keys()[0]
        cls.test_service_name = TestSetup.get_AnyServiceOfTestServiceType(cls)['service_name']

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    def setUp(self):
        self.check_requirements()

    @pytest.mark.status
    def test_Home(self):
        TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    def test_Login(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/login')

    @pytest.mark.status
    def test_ViewUsers(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/users')

    @pytest.mark.status
    def test_EditUser(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/users/anonymous/default')

    @pytest.mark.status
    def test_EditUserService(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/users/anonymous/{}'.format(self.test_service_type))

    @pytest.mark.status
    def test_ViewGroups(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/groups')

    @pytest.mark.status
    def test_EditGroup(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/groups/anonymous/default')

    @pytest.mark.status
    def test_EditGroupService(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/groups/anonymous/{}'.format(self.test_service_type))

    @pytest.mark.status
    def test_ViewService(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/services/default')

    @pytest.mark.status
    def test_ViewServiceSpecific(self):
        TestSetup.check_UpStatus(self, method='GET', path='/ui/services/{}'.format(self.test_service_type))

    @pytest.mark.status
    def test_EditService(self):
        path = '/ui/services/{type}/{name}'.format(type=self.test_service_type, name=self.test_service_name)
        TestSetup.check_UpStatus(self, method='GET', path=path)


test_cases = [
    TestMagpieUI_NoAuthLocal,
    TestMagpieUI_AdminAuthLocal,
    TestMagpieUI_NoAuthRemote,
    TestMagpieUI_AdminAuthRemote,
]


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for test_class in test_cases:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite
