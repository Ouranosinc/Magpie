#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_api
----------------------------------

Tests for ``magpie.api`` module.
"""

from magpie.constants import get_constant
from magpie.utils import CONTENT_TYPE_JSON
from tests import utils, runner

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti  # noqa: F401
import unittest


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieAPI_NoAuth_Local(ti.Interface_MagpieAPI_NoAuth, unittest.TestCase):
    """
    Test any operation that do not require any AuthN/AuthZ (``MAGPIE_ANONYMOUS_GROUP`` & ``MAGPIE_ANONYMOUS_USER``).
    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.json_headers = utils.get_headers(cls.app, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.usr = get_constant("MAGPIE_ANONYMOUS_USER")
        cls.grp = get_constant("MAGPIE_ANONYMOUS_GROUP")


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieAPI_UsersAuth_Local(ti.Interface_MagpieAPI_UsersAuth, unittest.TestCase):
    """
    Test any operation that require at least ``MAGPIE_USERS_GROUP`` AuthN/AuthZ.
    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieAPI_AdminAuth_Local(ti.Interface_MagpieAPI_AdminAuth, unittest.TestCase):
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.
    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.json_headers = utils.get_headers(cls.app, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        # TODO: fix UI views so that they can be "found" directly in the WebTest.TestApp
        # NOTE: localhost magpie has to be running for following login call to work
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd,
                                                                 use_ui_form_submit=True, version=cls.version)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.check_requirements()
        cls.setup_test_values()


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieAPI_NoAuth_Remote(ti.Interface_MagpieAPI_NoAuth, unittest.TestCase):
    """
    Test any operation that do not require any AuthN/AuthZ (``MAGPIE_ANONYMOUS_GROUP`` & ``MAGPIE_ANONYMOUS_USER``).
    Use an already running remote bird server.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.json_headers = utils.get_headers(cls.url, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.cookies = None
        cls.usr = get_constant("MAGPIE_ANONYMOUS_USER")
        cls.grp = get_constant("MAGPIE_ANONYMOUS_GROUP")
        cls.version = utils.TestSetup.get_Version(cls)


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieAPI_UsersAuth_Remote(ti.Interface_MagpieAPI_UsersAuth, unittest.TestCase):
    """
    Test any operation that require at least ``MAGPIE_USERS_GROUP`` AuthN/AuthZ.
    Use an already running remote bird server.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieAPI_AdminAuth_Remote(ti.Interface_MagpieAPI_AdminAuth, unittest.TestCase):
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.
    Use an already running remote bird server.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.json_headers = utils.get_headers(cls.url, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.version = utils.TestSetup.get_Version(cls)
        cls.check_requirements()
        cls.setup_test_values()


if __name__ == "__main__":
    import sys
    sys.exit(unittest.main())
