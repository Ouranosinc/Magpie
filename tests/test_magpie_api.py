#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_api
----------------------------------

Tests for `magpie.api` module.
"""

import unittest
import pytest
from magpie.constants import get_constant
from magpie import __meta__
from tests import utils, runner

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti


@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('api'))
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('local'))
class TestMagpieAPI_NoAuth_Local(ti.TestMagpieAPI_NoAuth_Interface):
    """
    Test any operation that do not require user AuthN/AuthZ.
    Use a local Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.json_headers = utils.get_headers_content_type(cls.app, 'application/json')
        cls.version = __meta__.__version__
        cls.cookies = None
        cls.usr = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.grp = get_constant('MAGPIE_ANONYMOUS_GROUP')


@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('api'))
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('local'))
class TestMagpieAPI_UsersAuth_Local(ti.TestMagpieAPI_UsersAuth_Interface):
    """
    Test any operation that require at least 'Users' group AuthN/AuthZ.
    Use a local Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()


@pytest.mark.api
@pytest.mark.local
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('api'))
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('local'))
class TestMagpieAPI_AdminAuth_Local(ti.TestMagpieAPI_AdminAuth_Interface):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    Use a local Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.grp = get_constant('MAGPIE_ADMIN_GROUP')
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.json_headers = utils.get_headers_content_type(cls.app, 'application/json')
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        # TODO: fix UI views so that they can be 'found' directly in the WebTest.TestApp
        # NOTE: localhost magpie has to be running for following login call to work
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd,
                                                                 use_ui_form_submit=False, version=cls.version)
        cls.require = "cannot run tests without logged in '{}' user".format(cls.grp)
        cls.check_requirements()
        cls.get_test_values()


@pytest.mark.api
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('api'))
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('remote'))
class TestMagpieAPI_NoAuth_Remote(ti.TestMagpieAPI_NoAuth_Interface):
    """
    Test any operation that do not require user AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.json_headers = utils.get_headers_content_type(cls.url, 'application/json')
        cls.cookies = None
        cls.usr = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.grp = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.version = utils.TestSetup.get_Version(cls)


@pytest.mark.api
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('api'))
@unittest.skipUnless(runner.MAGPIE_TEST_LOCAL, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('remote'))
class TestMagpieAPI_UsersAuth_Remote(ti.TestMagpieAPI_UsersAuth_Interface):
    """
    Test any operation that require at least 'Users' group AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()


@pytest.mark.api
@pytest.mark.remote
@unittest.skipUnless(runner.MAGPIE_TEST_API, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('api'))
@unittest.skipUnless(runner.MAGPIE_TEST_REMOTE, reason=runner.MAGPIE_TEST_DISABLED_MESSAGE('remote'))
class TestMagpieAPI_AdminAuth_Remote(ti.TestMagpieAPI_AdminAuth_Interface):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant('MAGPIE_ADMIN_GROUP')
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(cls.grp)
        cls.json_headers = utils.get_headers_content_type(cls.url, 'application/json')
        cls.version = utils.TestSetup.get_Version(cls)
        cls.check_requirements()
        cls.get_test_values()


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
