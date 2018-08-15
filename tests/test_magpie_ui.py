#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_ui
----------------------------------

Tests for `magpie.ui` module.
"""

import unittest
import pytest
import pyramid.testing
from magpie.constants import get_constant
from tests import utils, runner


@pytest.mark.ui
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason="Skip 'ui' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieUI_NoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = utils.get_headers_content_type(cls.app, 'application/json')
        cls.cookies = None
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = 'wps'
        cls.test_service_name = 'flyingpigeon'

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/login')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewUsers(self):
        utils.TestSetup.check_Unauthorized(self, method='GET', path='/ui/users')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewGroups(self):
        utils.TestSetup.check_Unauthorized(self, method='GET', path='/ui/groups')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewServices(self):
        utils.TestSetup.check_Unauthorized(self, method='GET', path='/ui/services/default')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewServicesOfType(self):
        path = '/ui/services/{}'.format(self.test_service_type)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditUser(self):
        path = '/ui/users/{}/default'.format(self.test_user)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditGroup(self):
        path = '/ui/groups/{}/default'.format(self.test_group)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditService(self):
        path = '/ui/services/{type}/{name}'.format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_Unauthorized(self, method='GET', path=path)


@pytest.mark.ui
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason="Skip 'ui' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason="Skip 'local' tests requested.")
class TestMagpieUI_AdminAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = utils.get_headers_content_type(cls.url, 'application/json')
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        # TODO: fix UI views so that they can be 'found' directly in the WebTest.TestApp
        # NOTE: localhost magpie has to be running for following login call to work
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in '{}' user".format(get_constant('MAGPIE_ADMIN_GROUP'))
        cls.check_requirements()

        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = utils.get_service_types_for_version(cls.version)[0]
        cls.test_service_name = utils.TestSetup.get_AnyServiceOfTestServiceType(cls)['service_name']

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/login')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewUsers(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/users')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewGroups(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/groups')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewServices(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/services/default')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewServicesOfType(self):
        path = '/ui/services/{}'.format(self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditUser(self):
        path = '/ui/users/{}/default'.format(self.test_user)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditGroup(self):
        path = '/ui/groups/{}/default'.format(self.test_group)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditService(self):
        path = '/ui/services/{type}/{name}'.format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)


@pytest.mark.ui
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason="Skip 'ui' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason="Skip 'remote' tests requested.")
class TestMagpieUI_NoAuthRemote(unittest.TestCase):
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

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/login')


@pytest.mark.ui
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason="Skip 'ui' tests requested.")
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason="Skip 'remote' tests requested.")
class TestMagpieUI_AdminAuthRemote(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(get_constant('MAGPIE_ADMIN_GROUP'))
        cls.json_headers = utils.get_headers_content_type(cls.url, 'application/json')
        cls.check_requirements()
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = utils.get_service_types_for_version(cls.version)[0]
        cls.test_service_name = utils.TestSetup.get_AnyServiceOfTestServiceType(cls)['service_name']

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    def setUp(self):
        self.check_requirements()

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/login')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewUsers(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/users')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditUser(self):
        path = '/ui/users/{usr}/default'.format(usr=self.test_user)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditUserService(self):
        path = '/ui/users/{usr}/{type}'.format(usr=self.test_user, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewGroups(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/groups')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditGroup(self):
        path = '/ui/groups/{grp}/default'.format(grp=self.test_group)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditGroupService(self):
        path = '/ui/groups/{grp}/{type}'.format(grp=self.test_group, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewService(self):
        utils.TestSetup.check_UpStatus(self, method='GET', path='/ui/services/default')

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_ViewServiceSpecific(self):
        path = '/ui/services/{type}'.format(type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)

    @pytest.mark.status
    @unittest.skipUnless(runner.MAGPIE_TEST_STATUS, reason="Skip 'status' tests requested.")
    def test_EditService(self):
        path = '/ui/services/{type}/{name}'.format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_UpStatus(self, method='GET', path=path)
