#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_api
----------------------------------

Tests for :mod:`magpie.api` module.
"""

import unittest

import mock

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti  # noqa: F401
from magpie.constants import get_constant
from magpie.utils import CONTENT_TYPE_JSON
from tests import runner, utils


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieAPI_NoAuth_Local(ti.Interface_MagpieAPI_NoAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that do not require any AuthN/AuthZ (``MAGPIE_ANONYMOUS_GROUP`` & ``MAGPIE_ANONYMOUS_USER``).

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def initClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.json_headers = utils.get_headers(cls.app, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.usr = get_constant("MAGPIE_ANONYMOUS_USER")
        cls.grp = get_constant("MAGPIE_ANONYMOUS_GROUP")


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieAPI_UsersAuth_Local(ti.Interface_MagpieAPI_UsersAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require logged AuthN/AuthZ, but lower than ``MAGPIE_ADMIN_GROUP``.

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def initClass(cls):
        cls.app = utils.get_test_magpie_app()
        # admin login credentials for setup operations, use 'test' parameters for testing actual feature
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.json_headers = utils.get_headers(cls.app, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd,
                                                                 use_ui_form_submit=True, version=cls.version)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.check_requirements()

        cls.test_user_group = get_constant("MAGPIE_USERS_GROUP")
        cls.test_user_name = "unittest-user_user-auth-username"
        cls.other_user_name = "unittest-other_user-auth-username"

    @classmethod
    def login_test_user(cls):
        utils.check_or_try_logout_user(cls)
        return utils.check_or_try_login_user(
            cls, username=cls.test_user_name, password=cls.test_user_name,
            use_ui_form_submit=True, version=cls.version)


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieAPI_AdminAuth_Local(ti.Interface_MagpieAPI_AdminAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def initClass(cls):
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
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that do not require any AuthN/AuthZ (``MAGPIE_ANONYMOUS_GROUP`` & ``MAGPIE_ANONYMOUS_USER``).

    Use an already running remote bird server.
    """

    __test__ = True

    @classmethod
    def initClass(cls):
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.json_headers = utils.get_headers(cls.url, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.cookies = None
        cls.usr = get_constant("MAGPIE_ANONYMOUS_USER")
        cls.grp = get_constant("MAGPIE_ANONYMOUS_GROUP")
        cls.version = utils.TestSetup.get_Version(cls)


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieAPI_UsersAuth_Remote(ti.Interface_MagpieAPI_UsersAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require logged user AuthN/AuthZ, but lower than ``MAGPIE_ADMIN_GROUP``.

    Use an already running remote bird server.
    """

    __test__ = True

    @classmethod
    def initClass(cls):
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieAPI_AdminAuth_Remote(ti.Interface_MagpieAPI_AdminAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.

    Use an already running remote bird server.
    """

    __test__ = True

    @classmethod
    def initClass(cls):
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


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
def test_magpie_homepage():
    from magpie.constants import get_constant as real_get_constant  # pylint: disable=W0404,reimported

    def mock_get_constant(*args, **kwargs):
        if args[0] == "MAGPIE_UI_ENABLED":
            return False
        return real_get_constant(*args, **kwargs)

    with mock.patch("magpie.constants.get_constant", side_effect=mock_get_constant), \
            mock.patch("magpie.api.home.get_constant", side_effect=mock_get_constant):
        app = utils.get_test_magpie_app()
        resp = utils.test_request(app, "GET", "/")
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("name", body)
        utils.check_val_is_in("title", body)
        utils.check_val_is_in("contact", body)
        utils.check_val_is_in("description", body)
        utils.check_val_is_in("documentation", body)
        utils.check_val_is_in("magpie", body["name"])


if __name__ == "__main__":
    import sys
    sys.exit(unittest.main())
