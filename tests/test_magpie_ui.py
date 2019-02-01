#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_ui
----------------------------------

Tests for `magpie.ui` module.
"""

import unittest
import pytest
from magpie.constants import get_constant
from tests import utils, runner

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti


@pytest.mark.ui
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('ui'))
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('local'))
class TestCase_MagpieUI_NoAuth_Local(ti.Interface_MagpieUI_NoAuth, unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = utils.get_headers(cls.app, {'Accept': 'application/json',
                                                       'Content-Type': 'application/json'})
        cls.cookies = None
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = 'wps'
        cls.test_service_name = 'flyingpigeon'


@pytest.mark.ui
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('ui'))
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('local'))
class TestCase_MagpieUI_AdminAuth_Local(ti.Interface_MagpieUI_AdminAuth, unittest.TestCase):
    """
    Test any operation that require at least 'administrator' group AuthN/AuthZ.
    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant('MAGPIE_ADMIN_GROUP')
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = utils.get_headers(cls.app, {'Accept': 'application/json',
                                                       'Content-Type': 'application/json'})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        # TODO: fix UI views so that they can be 'found' directly in the WebTest.TestApp
        # NOTE: localhost magpie has to be running for following login call to work
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.check_requirements()

        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = utils.get_service_types_for_version(cls.version)[0]
        cls.test_service_name = utils.TestSetup.get_AnyServiceOfTestServiceType(cls)['service_name']


@pytest.mark.ui
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('ui'))
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('remote'))
class TestCase_MagpieUI_NoAuth_Remote(ti.Interface_MagpieUI_NoAuth, unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.json_headers = utils.get_headers(cls.url, {'Accept': 'application/json',
                                                       'Content-Type': 'application/json'})
        cls.cookies = None
        cls.usr = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = 'wps'
        cls.test_service_name = 'flyingpigeon'


@pytest.mark.ui
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_UI, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('ui'))
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('remote'))
class TestCase_MagpieUI_AdminAuth_Remote(ti.Interface_MagpieUI_AdminAuth, unittest.TestCase):
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
        cls.json_headers = utils.get_headers(cls.url, {'Accept': 'application/json',
                                                       'Content-Type': 'application/json'})
        cls.check_requirements()
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = utils.get_service_types_for_version(cls.version)[0]
        cls.test_service_name = utils.TestSetup.get_AnyServiceOfTestServiceType(cls)['service_name']
