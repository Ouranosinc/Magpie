import os
import unittest
import warnings
from abc import ABCMeta, abstractmethod
from copy import deepcopy
from distutils.version import LooseVersion
from typing import TYPE_CHECKING

import mock
import pyramid.testing
import pytest
import six
import yaml
from six.moves.urllib.parse import urlparse

from magpie.api import schemas as s
from magpie.constants import MAGPIE_ROOT, get_constant
from magpie.models import RESOURCE_TYPE_DICT, Route
from magpie.permissions import Permission
from magpie.services import SERVICE_TYPE_DICT, ServiceAccess, ServiceAPI, ServiceTHREDDS
from magpie.utils import CONTENT_TYPE_HTML, CONTENT_TYPE_TXT_XML, CONTENT_TYPE_JSON, get_twitcher_protected_service_url
from tests import runner, utils

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import CookiesType, HeadersType, JSON, List, Optional, Str


class Base_Magpie_TestCase(six.with_metaclass(ABCMeta, unittest.TestCase)):
    """
    Base definition for all other `Test Case` interfaces.

    The implementers must provide :meth:`setUpClass` which prepares the various test parameters, session cookies and
    the local application or remote Magpie URL configuration to evaluate test cases on.

    The implementing `Test Case` must also set :attr:`__test__` to ``True`` so that tests are picked up as executable.

    .. note::
        Attribute attr:`__test__` is employed to avoid duplicate runs of this base class or other derived classes that
        must not be considered as the *final implementer* `Test Case`.
    """
    # pylint: disable=C0103,invalid-name

    # note: all following should be overridden by Test Case accordingly to the needs of their unit tests
    version = None              # type: Optional[Str]
    require = None              # type: Optional[Str]
    # parameters for setup operations, admin-level access to the app
    grp = None                  # type: Optional[Str]
    usr = None                  # type: Optional[Str]
    pwd = None                  # type: Optional[Str]
    cookies = None              # type: Optional[CookiesType]
    headers = None              # type: Optional[HeadersType]
    json_headers = None         # type: Optional[HeadersType]
    # parameters for testing, extracted automatically within 'utils.TestSetup' methods
    test_service_type = None    # type: Optional[Str]
    test_service_name = None    # type: Optional[Str]
    test_resource_name = None   # type: Optional[Str]
    test_resource_type = None   # type: Optional[Str]
    test_user_name = None       # type: Optional[Str]  # reuse as password to simplify calls when creating test user
    test_group_name = None      # type: Optional[Str]
    # extra parameters to indicate cleanup on final tear down
    # add new test values on test case startup before they *potentially* get interrupted because of error
    extra_user_names = []       # type: List[Str]
    extra_group_names = []      # type: List[Str]
    extra_resource_ids = []     # type: List[int]
    extra_service_names = []    # type: List[Str]

    __test__ = False    # won't run this as a test case, only its derived classes that overrides to True

    @classmethod
    @abstractmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        """
        Cleans up any left-over known object prefixed by ``test_`` as well as any other items added to lists
        prefixed by ``extra_``, in case some test failed to do so (e.g.: because it raised midway).
        """
        utils.check_or_try_logout_user(cls)
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls, username=cls.usr, password=cls.pwd)
        utils.TestSetup.delete_TestServiceResource(cls)
        utils.TestSetup.delete_TestService(cls)
        # avoid attempt cleanup of reserved keyword user/group, since it will fail with magpie '>=2.x'
        reserved_users = [get_constant("MAGPIE_ADMIN_USER"), get_constant("MAGPIE_ANONYMOUS_USER")]
        reserved_groups = [get_constant("MAGPIE_ADMIN_GROUP"), get_constant("MAGPIE_ANONYMOUS_GROUP")]
        cls.extra_user_names.append(cls.test_user_name)
        cls.extra_group_names.append(cls.test_group_name)
        for usr in cls.extra_user_names:
            if usr not in reserved_users:
                utils.TestSetup.delete_TestUser(cls, override_user_name=usr)
        for grp in cls.extra_group_names:
            if grp not in reserved_groups:
                utils.TestSetup.delete_TestGroup(cls, override_group_name=grp)
        for svc in cls.extra_service_names:
            utils.TestSetup.delete_TestService(cls, override_service_name=svc)
        for res in cls.extra_resource_ids:
            utils.TestSetup.delete_TestResource(cls, res)
        pyramid.testing.tearDown()

    @property
    def update_method(self):
        if LooseVersion(self.version) >= LooseVersion("2.0.0"):
            return "PATCH"
        return "PUT"


class User_Magpie_TestCase(object):
    """Extension of :class:`Base_Magpie_TestCase` to handle another user session than the administrator-level user."""
    usr = None              # type: Optional[Str]
    pwd = None              # type: Optional[Str]
    grp = None              # type: Optional[Str]
    version = None          # type: Optional[Str]
    cookies = None          # type: Optional[CookiesType]
    headers = None          # type: Optional[HeadersType]
    test_cookies = None     # type: Optional[CookiesType]
    test_headers = None     # type: Optional[HeadersType]
    test_user_name = None   # type: Optional[Str]
    test_group_name = None  # type: Optional[Str]

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    def setUp(self):
        """
        Login as admin to setup test items from fresh start and remain logged in as admin since test cases might need
        to setup additional items. Each test **MUST** call :meth:`login_test_user` before testing when finished setup.

        Ensure that test user will have test group membership but not admin-level access.
        """
        utils.check_or_try_logout_user(self)  # force logout user of previous test-case (e.g.: non-admin test-user)
        utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)   # login as admin to setup
        # cleanup anything that could be left over (e.g.: previous failing test run)
        utils.TestSetup.delete_TestGroup(self)
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestService(self)
        # setup minimal test user requirements
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        admin_group = get_constant("MAGPIE_ADMIN_GROUP")
        utils.TestSetup.check_UserGroupMembership(self, member=False, override_group_name=admin_group)
        utils.TestSetup.check_UserGroupMembership(self, member=True, override_group_name=self.test_group_name)

    def tearDown(self):
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestGroup(self)

    def login_test_user(self):
        # type: () -> utils.OptionalHeaderCookiesType
        """
        Obtain headers and cookies with session credentials of the test user (non administrator).
        The operation assumes that the test user already exists.
        Only validates that user does not have administrator privileges for integrity.

        Test headers and test cookies entries are updated in the extended class after successful execution.
        They are also returned.

        .. warning::
            Must ensure that administrator user (for setup operations) is logged out completely to avoid invalid tests.
            This is particularly important in the case of local TestApp that can store the session for one active user.

        :raises AssertionError: if test user could not be logged in or is an administrator
        """
        utils.check_or_try_logout_user(self)
        self.test_headers, self.test_cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=self.test_user_name,
            use_ui_form_submit=True, version=self.version)
        for header in ["Location", "Content-Type", "Content-Length"]:
            self.test_headers.pop(header, None)
        assert self.test_cookies, "Cannot test user-level access routes without logged user"
        return self.test_headers, self.test_cookies


@runner.MAGPIE_TEST_API
class Interface_MagpieAPI_NoAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that do not require user AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    def setUp(self):
        # validate on each new test-case that we are not logged in from invalid operation of some previous test
        utils.check_or_try_logout_user(self, msg="must be anonymous to evaluate this test case")

    @runner.MAGPIE_TEST_LOGIN
    def test_GetSession_Anonymous(self):
        resp = utils.test_request(self, "GET", "/session", headers=self.json_headers)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)
        # current format (with below as sub-fields)
        utils.check_val_not_in("user", body)
        # pre 0.6.3, fields were directly in body
        utils.check_val_not_in("user_name", body)
        utils.check_val_not_in("user_email", body)
        utils.check_val_not_in("group_names", body)

    @runner.MAGPIE_TEST_STATUS
    def test_GetVersion(self):
        resp = utils.test_request(self, "GET", "/version", headers=self.json_headers)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("db_version", body)
        utils.check_val_is_in("version", body)
        # server not necessarily at latest version, ensure at least format
        utils.check_val_equal(body["version"], self.version)
        utils.check_val_type(body["version"], six.string_types)
        version_parts = body["version"].split(".")
        utils.check_val_equal(len(version_parts), 3)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_GetCurrentUser(self):
        logged_user = get_constant("MAGPIE_LOGGED_USER")
        resp = utils.test_request(self, "GET", "/users/{}".format(logged_user), headers=self.json_headers)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)

    @runner.MAGPIE_TEST_STATUS
    def test_NotAcceptableRequest(self):
        utils.warn_version(self, "Unsupported 'Accept' header returns 406 directly.", "0.10.0", skip=True)
        for path in ["/session", "/users/current"]:
            resp = utils.test_request(self, "GET", path, expect_errors=True,
                                      headers={"Accept": "application/pdf"})  # anything not supported
            utils.check_response_basic_info(resp, expected_code=406, version=self.version)

    @runner.MAGPIE_TEST_STATUS
    def test_AcceptHeaderFormatQuery(self):
        warn_msg = "Request desired response content-type from 'Accept' header or 'format' query ."
        utils.warn_version(self, warn_msg, "2.0.0", skip=True)

        # using Accept header
        resp = utils.test_request(self, "GET", "/session", headers={"Accept": CONTENT_TYPE_JSON})
        body = utils.check_response_basic_info(resp, expected_type=CONTENT_TYPE_JSON)
        utils.check_val_type(body, dict)
        resp = utils.test_request(self, "GET", "/session", headers={"Accept": CONTENT_TYPE_TXT_XML})
        body = utils.check_response_basic_info(resp, expected_type=CONTENT_TYPE_TXT_XML)
        utils.check_val_is_in("<?xml", body)
        resp = utils.test_request(self, "GET", "/session", headers={"Accept": CONTENT_TYPE_HTML})
        body = utils.check_response_basic_info(resp, expected_type=CONTENT_TYPE_HTML)
        utils.check_val_is_in("<html>", body)

        # using format query
        resp = utils.test_request(self, "GET", "/session?format=json", headers={"Accept": ""})
        body = utils.check_response_basic_info(resp, expected_type=CONTENT_TYPE_JSON)
        utils.check_val_type(body, dict)
        resp = utils.test_request(self, "GET", "/session?format=xml", headers={"Accept": ""})
        body = utils.check_response_basic_info(resp, expected_type=CONTENT_TYPE_TXT_XML)
        utils.check_val_is_in("<?xml", body)
        resp = utils.test_request(self, "GET", "/session?format=html", headers=None)
        body = utils.check_response_basic_info(resp, expected_type=CONTENT_TYPE_HTML)
        utils.check_val_is_in("<html>", body)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_REGISTER
    def test_RegisterDiscoverableGroup_Unauthorized(self):
        """Not logged-in user cannot update membership to group although group is discoverable."""
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        resp = utils.test_request(self, "GET", "/register/groups", headers=self.json_headers, expect_errors=True)
        body = utils.check_response_basic_info(resp, 401)
        utils.check_val_not_in("group_names", body)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_REGISTER
    def test_UnregisterDiscoverableGroup_Unauthorized(self):
        """Not logged-in user cannot remove membership to group although group is discoverable."""
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        path = "/register/groups/random-group"
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, 401, expected_method="DELETE")

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_REGISTER
    def test_ViewDiscoverableGroup_Unauthorized(self):
        """Not logged-in user cannot view group although group is discoverable."""
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        admin_headers, admin_cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)

        # setup some actual discoverable group to ensure the error is not caused by some misinterpreted response
        test_group = "unittest-no-auth_test-group"
        self.extra_group_names.append(test_group)
        group_data = {"group_name": test_group, "discoverable": True}
        utils.TestSetup.delete_TestGroup(self, override_group_name=test_group)
        utils.TestSetup.create_TestGroup(self, override_data=group_data,
                                         override_headers=admin_headers, override_cookies=admin_cookies)
        utils.check_or_try_logout_user(self)

        path = "/register/groups/{}".format(test_group)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, 401, expected_method="DELETE")

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_REGISTER
    def test_ListDiscoverableGroup_Unauthorized(self):
        """Not logged-in user cannot list group names although groups are discoverable."""
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        resp = utils.test_request(self, "GET", "/register/groups", headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, 401)


@runner.MAGPIE_TEST_API
class Interface_MagpieAPI_UsersAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase, User_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that require at least logged user AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        super(Interface_MagpieAPI_UsersAuth, cls).tearDownClass()

    def setUp(self):
        User_Magpie_TestCase.setUp(self)

    def tearDown(self):
        utils.check_or_try_logout_user(self)

    def login_test_user(self):
        """Apply JSON headers on top of login headers for API calls."""
        User_Magpie_TestCase.login_test_user(self)
        self.test_headers.update(self.json_headers)
        return self.test_headers, self.test_cookies

    def test_PostSignin_EmailAsUsername(self):
        """User is allowed to use its email as username for login."""
        User_Magpie_TestCase.login_test_user(self)
        info = utils.TestSetup.get_UserInfo(self,
                                            override_headers=self.test_headers,
                                            override_cookies=self.test_cookies)
        utils.check_val_is_in(self.test_user_name, info["email"])
        utils.check_or_try_logout_user(self)
        data = {"user_name": info["email"], "password": self.test_user_name}
        resp = utils.test_request(self, "POST", "/signin", data=data, headers=self.json_headers, cookies={})
        body = utils.check_response_basic_info(resp, expected_method="POST")
        utils.check_val_equal(body["detail"], s.Signin_POST_OkResponseSchema.description)

    def test_PostSignin_MissingCredentials(self):
        """Signin attempt with missing returns bad request, not internal server error nor """
        utils.warn_version(self, "signin missing credentials status code check", "2.0.0", skip=False)
        utils.check_or_try_logout_user(self)

        data = {"user_name": self.usr}  # missing required password
        resp = utils.test_request(self, "POST", "/signin", data=data, expect_errors=True,
                                  headers=self.json_headers, cookies={})
        utils.check_response_basic_info(resp, expected_method="POST", expected_code=400)

    def test_GetSignin_UsingParameters(self):
        """User is allowed to use its email as username for login."""
        utils.warn_version(self, "signin using query parameters", "2.0.0", skip=True)
        utils.check_or_try_logout_user(self)

        queries = {"user_name": self.test_user_name, "password": self.test_user_name}
        resp = utils.test_request(self, "GET", "/signin", params=queries, headers={}, cookies={})
        body = utils.check_response_basic_info(resp)
        utils.check_val_equal(body["detail"], s.Signin_POST_OkResponseSchema.description)  # same as POST (redirect)

        resp_headers = getattr(resp, "headers", None)
        resp_cookies = getattr(resp, "cookies", None)
        resp = utils.test_request(self, "GET", "/session", headers=resp_headers, cookies=resp_cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)

    def run_PatchUsers_email_update_itself(self, user_path_variable):
        """
        Session user is allowed to update its own information via logged user path or corresponding user-name path.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_PatchUser_ReservedKeyword_Current`
        """
        self.login_test_user()

        # update existing user name
        new_email = "some-random-email@unittest.com"
        data = {"email": new_email}
        path = "/users/{usr}".format(usr=user_path_variable)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)

        # validate change
        info = utils.TestSetup.get_UserInfo(self,
                                            override_headers=self.test_headers,
                                            override_cookies=self.test_cookies)
        utils.check_val_equal(info["email"], new_email)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_PatchUsers_email_ReservedKeyword_Current(self):
        utils.warn_version(self, "user update own information", "2.0.0", skip=True)
        self.run_PatchUsers_email_update_itself(get_constant("MAGPIE_LOGGED_USER"))

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_email_MatchingUserName_Current(self):
        utils.warn_version(self, "user update own information", "2.0.0", skip=True)
        self.run_PatchUsers_email_update_itself(self.test_user_name)

    def run_PatchUsers_password_update_itself(self, user_path_variable):
        """
        Session user is allowed to update its own information via logged user path or corresponding user-name path.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_PatchUser_ReservedKeyword_Current`
        """
        self.login_test_user()

        old_password = self.test_user_name
        new_password = "n0t-SO-ez-2-Cr4cK"  # nosec
        data = {"password": new_password}
        path = "/users/{usr}".format(usr=user_path_variable)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)
        utils.check_or_try_logout_user(self)

        # validate that the new password is effective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=new_password,
            use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)
        utils.check_or_try_logout_user(self)

        # validate that previous password is ineffective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=old_password, version=self.version,
            use_ui_form_submit=True, expect_errors=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_PatchUsers_password_ReservedKeyword_Current(self):
        utils.warn_version(self, "user update own information ", "2.0.0", skip=True)
        self.run_PatchUsers_password_update_itself(get_constant("MAGPIE_LOGGED_USER"))

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_password_MatchingUserName_Current(self):
        utils.warn_version(self, "user update own information ", "2.0.0", skip=True)
        self.run_PatchUsers_password_update_itself(self.test_user_name)

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_password_Forbidden_UpdateOthers(self):
        """
        Although session user is allowed to update its own information, insufficient permissions (not admin) forbids
        that user to update other user's information.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_PatchUser_ReservedKeyword_Current`
        """
        utils.warn_version(self, "user update own information ", "2.0.0", skip=True)
        other_user_name = "unittest-user-auth_other-user-username"
        self.extra_user_names.append(other_user_name)
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user_name)
        utils.TestSetup.create_TestUser(self,
                                        override_user_name=other_user_name,
                                        override_password=other_user_name)
        self.login_test_user()

        new_password = "n0t-SO-ez-2-Cr4cK"  # nosec
        data = {"password": new_password}
        path = "/users/{usr}".format(usr=other_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)

        # validate that current user password was not randomly updated
        # make sure we clear any potential leftover cookies by re-login
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=self.test_user_name,
            use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)

        # validate that the new password was not applied to other user
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(
            self, username=other_user_name, password=other_user_name,
            use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], other_user_name)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_PatchUsers_username_Forbidden_ReservedKeyword_Current(self):
        """Logged user is not allowed to update its user name to reserved keyword."""
        self.login_test_user()
        data = {"user_name": get_constant("MAGPIE_LOGGED_USER")}
        resp = utils.test_request(self, self.update_method, "/users/current", data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)
        info = utils.TestSetup.get_UserInfo(self,
                                            override_headers=self.test_headers,
                                            override_cookies=self.test_cookies)
        utils.check_val_equal(info["user_name"], self.test_user_name)

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_username_Forbidden_AnyNonAdmin(self):
        """Non-admin level user is not permitted to update its own user name."""
        new_user_name = self.test_user_name + "new-user-name"
        self.extra_user_names.append(new_user_name)
        utils.TestSetup.delete_TestUser(self, override_user_name=new_user_name)
        self.login_test_user()

        data = {"user_name": new_user_name}
        resp = utils.test_request(self, self.update_method, "/users/current", data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)
        info = utils.TestSetup.get_UserInfo(self,
                                            override_headers=self.test_headers,
                                            override_cookies=self.test_cookies)
        utils.check_val_equal(info["user_name"], self.test_user_name)

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_username_Forbidden_UpdateOthers(self):
        """Logged user is not allowed to update any other user's name."""
        other_user_name = "unittest-user-auth_other-user-username"
        self.extra_user_names.append(other_user_name)
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user_name)
        utils.TestSetup.create_TestUser(self,
                                        override_user_name=other_user_name,
                                        override_password=other_user_name)
        self.login_test_user()

        # actual test
        # does not even matter if other user exists or not, forbidden should be raised as soon as user mismatches
        new_test_user_name = other_user_name + "new-user-name"
        self.extra_user_names.append(new_test_user_name)
        data = {"user_name": new_test_user_name}
        path = "/users/{}".format(other_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)

        # valid other user not updated by test user, with admin access
        resp = utils.test_request(self, "GET", path, cookies=self.cookies, headers=self.json_headers)
        utils.check_response_basic_info(resp)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    def test_PostUserGroup_Forbidden_SelfAssignMembership(self):
        """
        Non-admin level user cannot change its own group memberships nor any other user's group memberships.
        (can only change is own discoverable groups memberships through register routes, but not this route)

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_PostUserGroup_AllowAdmin_SelfAssignMembership`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_RegisterDiscoverableGroup`
        """
        test_group_name = "unittest-users-auth_new-group-self-assign"
        self.extra_group_names.append(test_group_name)
        utils.TestSetup.create_TestGroup(self, override_group_name=test_group_name)
        self.login_test_user()

        path = "/users/{}/groups".format(self.test_user_name)
        data = {"group_name": test_group_name}
        resp = utils.test_request(self, "POST", path, data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, expected_method="POST", expected_code=403)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_PostUserResourcesPermissions_Forbidden(self):
        """Logged user without administrator access is not allowed to add resource permissions for itself."""
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        body = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        self.login_test_user()

        res_id = body["resource_id"]
        perm = Permission.READ.value
        data = {"permission_name": perm}
        path = "/users/current/resources/{}/permissions".format(res_id)
        resp = utils.test_request(self, "POST", path, data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method="POST")
        path = "/users/{}/resources/{}/permissions".format(self.test_user_name, res_id)
        resp = utils.test_request(self, "GET", path, cookies=self.cookies, headers=self.json_headers)
        body = utils.check_response_basic_info(resp)
        utils.check_val_not_in(perm, body["permission_names"])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    def test_RegisterDiscoverableGroup(self):
        """Non-admin logged user is allowed to update is membership to register to a discoverable group by itself."""
        utils.TestSetup.delete_TestGroup(self)
        utils.TestSetup.create_TestGroup(self, override_discoverable=True)
        self.login_test_user()

        path = "/register/groups/{}".format(self.test_group_name)
        resp = utils.test_request(self, "POST", path, data={}, headers=self.test_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.check_val_is_in("group_name", body)
        utils.check_val_is_in("user_name", body)
        utils.check_val_is_in(body["group_name"], self.test_group_name)
        utils.check_val_is_in(body["user_name"], self.test_user_name)

        # validate as admin that user was registered
        utils.check_or_try_logout_user(self)
        utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.check_UserGroupMembership(self, member=True,
                                                  override_headers=self.json_headers, override_cookies=self.cookies)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    def test_UnregisterDiscoverableGroup(self):
        """Non-admin logged user is allowed to revoke its membership to leave a discoverable group by itself."""
        utils.TestSetup.delete_TestGroup(self)
        utils.TestSetup.create_TestGroup(self, override_discoverable=True)
        utils.TestSetup.assign_TestUserGroup(self)
        self.login_test_user()

        path = "/register/groups/{}".format(self.test_group_name)
        resp = utils.test_request(self, "DELETE", path, data={}, headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")

        # validate as admin that user was unregistered
        utils.check_or_try_logout_user(self)
        utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.check_UserGroupMembership(self, member=False,
                                                  override_headers=self.json_headers, override_cookies=self.cookies)

    @runner.MAGPIE_TEST_GROUPS
    def test_ViewDiscoverableGroup(self):
        """Non-admin logged user can view discoverable group information. Critical details are not displayed."""
        data = {"discoverable": True, "description": "Test Group", "group_name": self.test_group_name}
        utils.TestSetup.delete_TestGroup(self)
        utils.TestSetup.create_TestGroup(self, override_data=data)
        self.login_test_user()

        path = "/register/groups/{}".format(self.test_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.test_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in("group", body)
        utils.check_val_is_in("group_name", body["group"])
        utils.check_val_is_in("description", body["group"])
        utils.check_val_equal(body["group"]["group_name"], self.test_group_name)
        utils.check_val_equal(body["group"]["description"], "Test Group")
        utils.check_val_not_in("group_id", body["group"])
        utils.check_val_not_in("discoverable", body["group"])
        utils.check_val_not_in("member_count", body["group"])
        utils.check_val_not_in("user_names", body["group"])

    @runner.MAGPIE_TEST_GROUPS
    def test_ListDiscoverableGroups_Filtered(self):
        """Non-admin logged user can view only available discoverable group names."""
        # setup some discoverable groups, but ignore others that *could* exist depending on the reference database
        # test user should have pre-assigned membership to non-discoverable test group (from setUp)
        # but that group must not be returned in the list of discoverable groups
        discover_before = set(utils.TestSetup.get_RegisteredGroupsList(self, only_discoverable=True))
        discover_groups = {self.test_group_name + "-1", self.test_group_name + "-2", self.test_group_name + "-3"}
        self.extra_group_names.extend(discover_groups)
        for grp in discover_groups:
            utils.TestSetup.delete_TestGroup(self, override_group_name=grp)  # in case previous test run failed/stopped
            utils.TestSetup.create_TestGroup(self, override_data={"discoverable": True, "group_name": grp})
            discover_before = discover_before - {grp}
        self.login_test_user()

        # test that only just added discoverable groups are visible (ignore pre-existing discoverable groups if any)
        resp = utils.test_request(self, "GET", "/register/groups", headers=self.test_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in("group_names", body)
        returned_groups = set(body["group_names"]) - discover_before
        utils.check_all_equal(discover_groups, returned_groups, any_order=True,
                              msg="Only discoverable groups should be listed for non-admin user, no more, no less.")
        # validate that anonymous doesn't come up in this list even though test user is a member of it
        # we do not even need to consider pre-existing discoverable groups as anonymous shouldn't be one
        utils.check_val_not_in(get_constant("MAGPIE_ANONYMOUS_GROUP"), body["group_names"])

    @runner.MAGPIE_TEST_GROUPS
    def test_DeleteDiscoverableGroup_Forbidden(self):
        """Non-admin logged user cannot delete a group although it is discoverable."""
        utils.TestSetup.delete_TestGroup(self)  # remove auto-created by setup
        utils.TestSetup.create_TestGroup(self, override_discoverable=True)
        self.login_test_user()

        path = "/register/groups/{}".format(self.test_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200)
        # test non-admin user cannot delete group
        path = "/groups/{}".format(self.test_group_name)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")
        # validate with admin access that group still exists
        utils.check_or_try_logout_user(self)
        utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        resp = utils.test_request(self, "GET", path, cookies=self.cookies, headers=self.headers)
        utils.check_response_basic_info(resp, 200)


@runner.MAGPIE_TEST_API
class Interface_MagpieAPI_AdminAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that require at least 'administrator' group
    AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    def tearDown(self):
        self.check_requirements()   # re-login as required in case test logged out the user with permissions
        utils.TestSetup.delete_TestServiceResource(self)
        utils.TestSetup.delete_TestService(self)
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestGroup(self)

    @classmethod
    def check_requirements(cls):
        utils.check_or_try_logout_user(cls)  # in case user changed during another test
        headers, cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd,
                                                         use_ui_form_submit=True, version=cls.version)
        assert headers and cookies, cls.require             # nosec
        assert cls.headers and cls.cookies, cls.require     # nosec
        cls.test_headers = cls.headers
        cls.test_cookies = cls.cookies

    @classmethod
    def setup_test_values(cls):
        provider_file = os.path.join(MAGPIE_ROOT, "config", "providers.cfg")
        services_cfg = yaml.safe_load(open(provider_file, "r"))
        provider_services_info = services_cfg["providers"]
        # filter impossible providers from possible previous version of remote server
        possible_service_types = utils.get_service_types_for_version(cls.version)
        cls.test_services_info = dict()
        for svc_name in provider_services_info:
            if provider_services_info[svc_name]["type"] in possible_service_types:
                cls.test_services_info[svc_name] = provider_services_info[svc_name]

        cls.test_service_name = "magpie-unittest-service-api"
        cls.test_service_type = ServiceAPI.service_type
        cls.test_service_perm = SERVICE_TYPE_DICT[cls.test_service_type].permissions[0].value
        utils.TestSetup.create_TestService(cls)

        cls.test_resource_name = "magpie-unittest-resource"
        test_service_res_perm_dict = SERVICE_TYPE_DICT[cls.test_service_type].resource_types_permissions
        test_service_resource_types = list(test_service_res_perm_dict.keys())
        utils.check_val_not_equal(len(test_service_resource_types), 0,
                                  msg="test service must allow at least 1 sub-resource for test execution")
        cls.test_resource_class = test_service_resource_types[0]
        cls.test_resource_type = cls.test_resource_class.resource_type_name
        cls.test_service_resource_perms = test_service_res_perm_dict[cls.test_resource_class]
        utils.check_val_not_equal(len(cls.test_service_resource_perms), 0,
                                  msg="test service must allow at least 1 sub-permission for test execution")
        cls.test_resource_perm_type = cls.test_service_resource_perms[0]
        cls.test_resource_perm_name = cls.test_resource_perm_type.value

        cls.test_group_name = "magpie-unittest-dummy-group"
        cls.test_user_name = "magpie-unittest-toto"

    def setUp(self):
        self.check_requirements()
        utils.TestSetup.delete_TestServiceResource(self)
        utils.TestSetup.delete_TestService(self)
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestGroup(self)

    def test_GetAPI(self):
        resp = utils.test_request(self, "GET", s.SwaggerGenerator.path, headers=self.json_headers)
        body = utils.get_json_body(resp)
        content_types = utils.get_response_content_types_list(resp)
        utils.check_val_is_in(CONTENT_TYPE_JSON, content_types)
        utils.check_val_equal(resp.status_code, 200)
        utils.check_val_is_in("info", body)
        utils.check_val_is_in("version", body["info"])
        utils.check_val_equal(body["info"]["version"], self.version)
        utils.check_val_is_in("paths", body)
        utils.check_val_is_in("host", body)
        utils.check_val_is_in("schemes", body)
        utils.check_val_is_in("tags", body)
        utils.check_val_is_in("basePath", body)
        utils.check_val_is_in("securityDefinitions", body)
        utils.check_val_is_in("swagger", body)
        utils.check_val_equal(body["swagger"], "2.0")

    @runner.MAGPIE_TEST_STATUS
    def test_unauthorized_forbidden_responses(self):
        """
        Verify that unauthorized (401) and forbidden (403) are properly returned for corresponding operations.

        Both variations use the same forbidden view.
        """
        utils.warn_version(self, "check for response (401/403) statuses", "0.9.1", skip=True)

        app_or_url = utils.get_app_or_url(self)
        if isinstance(app_or_url, six.string_types):
            warnings.warn("cannot validate 403 status with remote server (no mock possible, must test with local)",
                          RuntimeWarning)
        else:
            # call a route that will make a forbidden access to db
            with mock.patch("magpie.models.User", side_effect=Exception("Test")):
                resp = utils.test_request(self, "GET", "/users", headers=self.json_headers, expect_errors=True)
                body = utils.check_response_basic_info(resp, 403, expected_method="GET")
                utils.check_val_equal(body["code"], 403)

        # call a route that is admin-only
        utils.check_or_try_logout_user(app_or_url)
        resp = utils.test_request(self, "GET", "/services", headers=self.json_headers, expect_errors=True)
        body = utils.check_response_basic_info(resp, 401, expected_method="GET")
        utils.check_val_equal(body["code"], 401)

    @runner.MAGPIE_TEST_LOGIN
    def test_GetSession_Administrator(self):
        resp = utils.test_request(self, "GET", "/session", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_is_in("user", body)
        utils.check_val_equal(info["user_name"], self.usr)
        utils.check_val_is_in(get_constant("MAGPIE_ADMIN_GROUP"), info["group_names"])
        utils.check_val_type(info["group_names"], list)
        utils.check_val_is_in("email", info)

    @runner.MAGPIE_TEST_USERS
    def test_GetUsers(self):
        resp = utils.test_request(self, "GET", "/users", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_val_equal(len(body["user_names"]) > 1, True)     # should have more than only 'anonymous'
        utils.check_val_is_in("anonymous", body["user_names"])       # anonymous always in users
        utils.check_val_is_in(self.usr, body["user_names"])          # current test user in users

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_ValidateDefaultUsers(self):
        resp = utils.test_request(self, "GET", "/users", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        users = body["user_names"]
        utils.check_val_is_in(get_constant("MAGPIE_ANONYMOUS_USER"), users)
        utils.check_val_is_in(get_constant("MAGPIE_ADMIN_USER"), users)

    @classmethod
    def check_GetUserResourcesPermissions(cls, user_name, resource_id, query=None):
        query = "?{}".format(query) if query else ""
        path = "/users/{usr}/resources/{res}/permissions{q}".format(res=resource_id, usr=user_name, q=query)
        resp = utils.test_request(cls, "GET", path, headers=cls.json_headers, cookies=cls.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("permission_names", body)
        utils.check_val_type(body["permission_names"], list)
        return body

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_GetCurrentUser(self):
        logged_user = get_constant("MAGPIE_LOGGED_USER")
        path = "/users/{}".format(logged_user)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.usr)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_GetCurrentUserResourcesPermissions(self):
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        res_id = body["resource"]["resource_id"]
        self.check_GetUserResourcesPermissions(get_constant("MAGPIE_LOGGED_USER"), res_id)

    @runner.MAGPIE_TEST_USERS
    def test_GetCurrentUserResourcesPermissions_Queries(self):
        utils.warn_version(self, "permission effect queries", "0.7.0", skip=True)

        # setup test resources under service with permissions
        # Service/Resources              | Admin-User | Admin-Group | Anonym-User | Anonym-Group
        # ---------------------------------------------------------------------------------------
        # test-service                   | r          | r-m         |             | r
        #   |- test-resource (parent)    |            | r-m         |             |
        #       |- test-resource (child) |            |             | r-m         |
        body = utils.TestSetup.create_TestService(self, override_service_type=ServiceAPI.service_type)
        test_svc_res_id = body["service"]["resource_id"]
        test_res_type = Route.resource_type_name
        body = utils.TestSetup.create_TestServiceResource(self, override_resource_type=test_res_type)
        test_parent_res_id = body["resource"]["resource_id"]
        child_resource_name = self.test_resource_name + "-child"
        override_data = {
            "resource_name": child_resource_name,
            "resource_type": test_res_type,
            "parent_id": test_parent_res_id
        }
        body = utils.TestSetup.create_TestServiceResource(self, override_data=override_data)
        test_child_res_id = body["resource"]["resource_id"]
        anonym_usr = get_constant("MAGPIE_ANONYMOUS_USER")
        anonym_grp = get_constant("MAGPIE_ANONYMOUS_GROUP")

        perm_recur = Permission.READ.value
        perm_match = Permission.READ_MATCH.value
        data_recur = {"permission_name": perm_recur}
        data_match = {"permission_name": perm_match}
        path = "/users/{usr}/resources/{res}/permissions".format(res=test_svc_res_id, usr=self.usr)
        utils.test_request(self, "POST", path, data=data_recur, headers=self.json_headers, cookies=self.cookies)
        path = "/groups/{grp}/resources/{res}/permissions".format(res=test_svc_res_id, grp=self.grp)
        utils.test_request(self, "POST", path, data=data_match, headers=self.json_headers, cookies=self.cookies)
        path = "/groups/{grp}/resources/{res}/permissions".format(res=test_parent_res_id, grp=self.grp)
        utils.test_request(self, "POST", path, data=data_match, headers=self.json_headers, cookies=self.cookies)
        path = "/users/{usr}/resources/{res}/permissions".format(res=test_child_res_id, usr=anonym_usr)
        utils.test_request(self, "POST", path, data=data_match, headers=self.json_headers, cookies=self.cookies)
        path = "/groups/{grp}/resources/{res}/permissions".format(res=test_svc_res_id, grp=anonym_grp)
        utils.test_request(self, "POST", path, data=data_recur, headers=self.json_headers, cookies=self.cookies)

        # tests
        q_groups = "inherit=true"
        q_effect = "effective=true"
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=q_groups)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=q_effect)
        utils.check_val_equal(body["permission_names"], [perm_recur])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=q_groups)
        utils.check_val_equal(body["permission_names"], [perm_match])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=q_effect)
        utils.check_all_equal(body["permission_names"], [perm_recur, perm_match], any_order=True)
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [perm_recur])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=q_groups)
        utils.check_all_equal(body["permission_names"], [perm_recur, perm_match], any_order=True)
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=q_effect)
        utils.check_all_equal(body["permission_names"], [perm_recur, perm_match], any_order=True)

        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [perm_match])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=q_groups)
        utils.check_val_equal(body["permission_names"], [perm_match])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=q_effect)
        utils.check_all_equal(body["permission_names"], [perm_recur, perm_match], any_order=True)
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=q_groups)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=q_effect)
        utils.check_val_equal(body["permission_names"], [perm_recur])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=q_groups)
        utils.check_val_equal(body["permission_names"], [perm_recur])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=q_effect)
        utils.check_val_equal(body["permission_names"], [perm_recur])

    @runner.MAGPIE_TEST_USERS
    def test_GetUserResourcesPermissions(self):
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        self.check_GetUserResourcesPermissions(self.usr, body["resource"]["resource_id"])

    @runner.MAGPIE_TEST_USERS
    def test_PostUserResourcesPermissions_Created(self):
        resource_name = "post_res_perm_created"
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

        data = {"resource_name": resource_name}
        body = utils.TestSetup.create_TestServiceResource(self, override_data=data)
        test_res_id = body["resource"]["resource_id"]

        # test permission creation
        path = "/users/{usr}/resources/{res}/permissions".format(res=test_res_id, usr=self.usr)
        data = {"permission_name": self.test_resource_perm_name}
        resp = utils.test_request(self, "POST", path, data=data, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.check_val_is_in("permission_name", body)
        utils.check_val_is_in("resource_id", body)
        utils.check_val_is_in("user_id", body)
        utils.check_val_type(body["permission_name"], six.string_types)
        utils.check_val_type(body["resource_id"], int)
        utils.check_val_type(body["user_id"], int)

        # cleanup (delete sub resource should remove child permission)
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

    @runner.MAGPIE_TEST_USERS
    def test_PostUserResourcesPermissions_Conflict(self):
        resource_name = "post_res_perm_conflict"
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

        data = {"resource_name": resource_name}
        body = utils.TestSetup.create_TestServiceResource(self, override_data=data)
        test_res_id = body["resource"]["resource_id"]

        path = "/users/{usr}/resources/{res}/permissions".format(res=test_res_id, usr=self.usr)
        data = {"permission_name": self.test_resource_perm_name}
        utils.test_request(self, "POST", path, data=data, headers=self.json_headers, cookies=self.cookies)
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_res_id)
        utils.check_val_is_in(self.test_resource_perm_name, body["permission_names"],
                              msg="Can't test for conflicting permissions if it doesn't exist first.")

        resp = utils.test_request(self, "POST", path, data=data, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        body = utils.check_response_basic_info(resp, 409, expected_method="POST")
        utils.check_val_is_in("permission_name", body)
        utils.check_val_is_in("resource_id", body)
        utils.check_val_is_in("user_id", body)
        utils.check_val_type(body["permission_name"], six.string_types)
        utils.check_val_type(body["resource_id"], int)
        utils.check_val_type(body["user_id"], int)

        # cleanup (delete sub resource should remove child permission)
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)

    @runner.MAGPIE_TEST_USERS
    def test_GetCurrentUserGroups(self):
        resp = utils.test_request(self, "GET", "/users/current/groups",
                                  headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)
        utils.check_val_is_in(get_constant("MAGPIE_ADMIN_GROUP"), body["group_names"])

    def setup_UniquePermissionsForEach_UserGroupServiceResource(self):
        """
        Setups a new user, a new group, a new service and a new child resource of this service. The only member of the
        new group is the new user.

        For each variation of the created (user/group, service/resource), creates an unique permission.
        The user and group don't have any other permission than the ones above.

        Returns a tuple of all employed and generated information above.
        """
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        res_id = body["resource"]["resource_id"]
        all_perms = deepcopy(self.test_service_resource_perms)
        # different permissions on each resource to ensure proper resolution occurs
        perm_svc_usr = all_perms.pop().value
        perm_svc_grp = all_perms.pop().value
        perm_res_usr = all_perms.pop().value
        perm_res_grp = all_perms.pop().value
        utils.check_val_equal(len({perm_svc_usr, perm_svc_grp, perm_res_usr, perm_res_grp}), 4,
                              msg="All permissions must be different to properly evaluate test responses.")

        # add permission on direct service for user
        path = "/users/{usr}/services/{svc}/permissions".format(usr=self.test_user_name, svc=self.test_service_name)
        data = {"permission_name": perm_svc_usr}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        # add permission on direct service for group
        path = "/groups/{grp}/services/{svc}/permissions".format(grp=self.test_group_name, svc=self.test_service_name)
        data = {"permission_name": perm_svc_grp}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        # add permission on service resource for user
        path = "/users/{usr}/resources/{res}/permissions".format(usr=self.test_user_name, res=res_id)
        data = {"permission_name": perm_res_usr}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        # add permission on service resource for group
        path = "/groups/{grp}/resources/{res}/permissions".format(grp=self.test_group_name, res=res_id)
        data = {"permission_name": perm_res_grp}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        return (perm_svc_usr, perm_svc_grp, perm_res_usr, perm_res_grp,
                self.test_user_name, self.test_group_name, self.test_service_name, self.test_service_type, res_id)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserResources_OnlyUserAndInheritedGroupPermissions_values(self):
        values = self.setup_UniquePermissionsForEach_UserGroupServiceResource()
        perm_svc_usr, perm_svc_grp, perm_res_usr, perm_res_grp, usr_name, _, svc_name, svc_type, res_id = values

        # with or without inherit flag, "other" services and resources should all have no permission
        service_types = utils.get_service_types_for_version(self.version)
        service_type_no_perm = set(service_types) - {svc_type}
        utils.check_val_not_equal(len(service_type_no_perm), 0,
                                  msg="Cannot evaluate response values with insufficient service types.")
        for query in ["", "?inherit=true"]:
            path = "/users/{usr}/resources{q}".format(usr=usr_name, q=query)
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.check_val_is_in("resources", body)
            # Starting with 1.4.0, users are automatically members of anonymous group, and therefore
            # inherit their permissions. Find the number of anonymous-only permissions, there shouldn't be any other.
            resources_anonymous_body = {}
            if LooseVersion(self.version) >= LooseVersion("1.4.0") and query:
                path = "/groups/{grp}/resources".format(grp=get_constant("MAGPIE_ANONYMOUS_GROUP"))
                resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
                resources_anonymous_body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            # validation
            for svc_type_no_perm in service_type_no_perm:
                svc_type_body = body["resources"][svc_type_no_perm]  # type: JSON
                svc_type_services_anonymous = resources_anonymous_body.get("resources", {}).get(svc_type_no_perm, {})
                for svc_name_no_perm in svc_type_body:
                    # remove inherited anonymous-only group resources and permissions (see above)
                    svc_anonymous = svc_type_services_anonymous.get(svc_name_no_perm, {})
                    svc_res_anonymous = svc_anonymous.get("resources", {})
                    svc_res_test_user = svc_type_body[svc_name_no_perm]["resources"]
                    svc_res_ids_only_user = set(svc_res_test_user) - set(svc_res_anonymous)
                    utils.check_val_equal(len(svc_res_ids_only_user), 0,
                                          msg="User should not have any permitted resource under the service")
                    svc_perms_anonymous = svc_anonymous.get("permission_names", [])
                    svc_perms_test_user = svc_type_body[svc_name_no_perm]["permission_names"]  # noqa
                    svc_perms_only_user = set(svc_perms_test_user) - set(svc_perms_anonymous)
                    utils.check_val_equal(len(svc_perms_only_user), 0,
                                          msg="User should not have any service permissions")

        # without inherit flag, only direct user permissions are visible on service and resource
        path = "/users/{usr}/resources".format(usr=usr_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        test_service = body["resources"][svc_type][svc_name]  # type: JSON
        utils.check_val_equal(test_service["permission_names"], [perm_svc_usr])
        utils.check_val_is_in(str(res_id), test_service["resources"])
        test_perms = test_service["resources"][str(res_id)]["permission_names"]  # noqa
        utils.check_val_equal(test_perms, [perm_res_usr])

        # with inherit flag, both user and group permissions are visible on service and resource
        path = "/users/{usr}/resources?inherit=true".format(usr=usr_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        test_service = body["resources"][svc_type][svc_name]
        utils.check_all_equal(test_service["permission_names"], [perm_svc_usr, perm_svc_grp], any_order=True)
        utils.check_val_is_in(str(res_id), test_service["resources"])
        utils.check_all_equal(test_service["resources"][str(res_id)]["permission_names"],  # noqa
                              [perm_res_usr, perm_res_grp], any_order=True)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserInheritedResources_format(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            path = "/users/{usr}/inherited_resources".format(usr=self.usr)
        else:
            path = "/users/{usr}/resources?inherit=true".format(usr=self.usr)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("resources", body)
        utils.check_val_type(body["resources"], dict)
        service_types = utils.get_service_types_for_version(self.version)
        utils.check_all_equal(body["resources"].keys(), service_types, any_order=True)
        for svc_type in body["resources"]:
            for svc in body["resources"][svc_type]:
                svc_dict = body["resources"][svc_type][svc]  # type: JSON
                utils.check_val_type(svc_dict, dict)
                utils.check_val_is_in("resource_id", svc_dict)
                utils.check_val_is_in("service_name", svc_dict)
                utils.check_val_is_in("service_type", svc_dict)
                utils.check_val_is_in("public_url", svc_dict)
                utils.check_val_is_in("permission_names", svc_dict)
                utils.check_val_is_in("resources", svc_dict)
                utils.check_val_type(svc_dict["resource_id"], int)
                utils.check_val_type(svc_dict["service_name"], six.string_types)
                utils.check_val_type(svc_dict["service_type"], six.string_types)
                utils.check_val_type(svc_dict["public_url"], six.string_types)
                utils.check_val_type(svc_dict["permission_names"], list)
                utils.check_val_type(svc_dict["resources"], dict)
                if LooseVersion(self.version) >= LooseVersion("0.7.0"):
                    utils.check_val_is_in("service_sync_type", svc_dict)
                    utils.check_val_type(svc_dict["service_sync_type"], utils.OptionalStringType)
                    utils.check_val_not_in("service_url", svc_dict,
                                           msg="Services under user routes shouldn't show private url.")
                else:
                    utils.check_val_is_in("service_url", svc_dict)
                    utils.check_val_type(svc_dict["service_url"], six.string_types)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUserResourcePermission(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        res_id = body["resource"]["resource_id"]
        path = "/users/{usr}/resources/{res}/permissions".format(usr=self.test_user_name, res=res_id)
        data = {"permission_name": self.test_resource_perm_name}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 201, expected_method="POST")
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in(self.test_resource_perm_name, body["permission_names"])

        path_perm = "{path}/{perm}".format(path=path, perm=self.test_resource_perm_name)
        resp = utils.test_request(self, "DELETE", path_perm, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_not_in(self.test_resource_perm_name, body["permission_names"])

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUserServicePermission(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestService(self)
        path = "/users/{usr}/services/{svc}/permissions".format(usr=self.test_user_name, svc=self.test_service_name)
        data = {"permission_name": self.test_service_perm}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 201, expected_method="POST")
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in(self.test_service_perm, body["permission_names"])

        path_perm = "{path}/{perm}".format(path=path, perm=self.test_service_perm)
        resp = utils.test_request(self, "DELETE", path_perm, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_not_in(self.test_service_perm, body["permission_names"])

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServices(self):
        path = "/users/{usr}/services".format(usr=self.usr)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        services = body["services"]
        utils.check_val_type(services, dict)
        service_types = utils.get_service_types_for_version(self.version)
        # as of version 0.7.0, visible services depend on the connected user permissions,
        # so all services types not necessarily returned in the response
        if LooseVersion(self.version) < LooseVersion("0.7.0"):
            utils.check_all_equal(services.keys(), service_types, any_order=True)
        for svc_type in services:
            utils.check_val_is_in(svc_type, service_types)  # one of valid service types
            for svc in services[svc_type]:
                svc_dict = services[svc_type][svc]  # type: JSON
                utils.check_val_type(svc_dict, dict)
                utils.check_val_is_in("resource_id", svc_dict)
                utils.check_val_is_in("service_name", svc_dict)
                utils.check_val_is_in("service_type", svc_dict)
                utils.check_val_is_in("public_url", svc_dict)
                utils.check_val_is_in("permission_names", svc_dict)
                utils.check_val_type(svc_dict["resource_id"], int)
                utils.check_val_type(svc_dict["service_name"], six.string_types)
                utils.check_val_type(svc_dict["service_type"], six.string_types)
                utils.check_val_type(svc_dict["public_url"], six.string_types)
                utils.check_val_type(svc_dict["permission_names"], list)
                if LooseVersion(self.version) >= LooseVersion("0.7.0"):
                    utils.check_val_is_in("service_sync_type", svc_dict)
                    utils.check_val_type(svc_dict["service_sync_type"], utils.OptionalStringType)
                    utils.check_val_not_in("service_url", svc_dict,
                                           msg="Services under user routes shouldn't show private url.")
                else:
                    utils.check_val_is_in("service_url", svc_dict)
                    utils.check_val_type(svc_dict["service_url"], six.string_types)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServiceResources_format(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        path = "/users/{usr}/services/{svc}/resources".format(usr=self.usr, svc=self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("service", body)
        svc_dict = body["service"]
        utils.check_val_type(svc_dict, dict)
        utils.check_val_is_in("resource_id", svc_dict)
        utils.check_val_is_in("service_name", svc_dict)
        utils.check_val_is_in("service_type", svc_dict)
        utils.check_val_is_in("public_url", svc_dict)
        utils.check_val_is_in("permission_names", svc_dict)
        utils.check_val_is_in("resources", svc_dict)
        utils.check_val_type(svc_dict["resource_id"], int)
        utils.check_val_type(svc_dict["service_name"], six.string_types)
        utils.check_val_type(svc_dict["service_type"], six.string_types)
        utils.check_val_type(svc_dict["public_url"], six.string_types)
        utils.check_val_type(svc_dict["permission_names"], list)
        utils.check_val_type(svc_dict["resources"], dict)
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", svc_dict)
            utils.check_val_type(svc_dict["service_sync_type"], utils.OptionalStringType)
            utils.check_val_not_in("service_url", svc_dict)
        else:
            utils.check_val_is_in("service_url", svc_dict)
            utils.check_val_type(svc_dict["service_url"], six.string_types)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServiceResources_OnlyUserAndInheritedGroupPermissions_values(self):
        values = self.setup_UniquePermissionsForEach_UserGroupServiceResource()
        perm_svc_usr, perm_svc_grp, perm_res_usr, perm_res_grp, usr_name, _, svc_name, svc_type, res_id = values

        # without inherit flag, only user permissions are visible on service and resource
        path = "/users/{usr}/services/{svc}/resources".format(usr=usr_name, svc=svc_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["service"]["service_name"], svc_name)
        utils.check_val_equal(body["service"]["service_type"], svc_type)
        utils.check_val_equal(body["service"]["permission_names"], [perm_svc_usr])
        utils.check_val_is_in(str(res_id), body["service"]["resources"])
        utils.check_val_equal(body["service"]["resources"][str(res_id)]["permission_names"], [perm_res_usr])  # noqa

        # with inherit flag, both user and group permissions are visible on service and resource
        path = "/users/{usr}/services/{svc}/resources?inherit=true".format(usr=usr_name, svc=svc_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["service"]["service_name"], svc_name)
        utils.check_val_equal(body["service"]["service_type"], svc_type)
        utils.check_all_equal(body["service"]["permission_names"], [perm_svc_usr, perm_svc_grp], any_order=True)
        utils.check_val_is_in(str(res_id), body["service"]["resources"])
        utils.check_all_equal(body["service"]["resources"][str(res_id)]["permission_names"],  # noqa
                              [perm_res_usr, perm_res_grp], any_order=True)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PUBLIC
    def test_GetUserServiceResourcePermission_InheritedPublic_DirectPermission(self):
        """
        Tests that validates that non-admin user can obtain some specific resource permission via anonymous group
        permission applied by admin directly on that resource.
        """
        # setup
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body, full_detail=True)
        applicable_perm = info["permission_names"][0]
        res_id = body["resource_id"]
        path = "groups/{}/resources/{}/permissions".format(get_constant("MAGPIE_ANONYMOUS_GROUP"), res_id)
        resp = utils.test_request(self, "POST", path, json={"permission_name": applicable_perm})
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        # test
        path = "/users/{}/resources/{}/permissions?effective=true".format(self.test_user_name, res_id)
        resp = utils.test_request(self, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("permission_names", body)
        utils.check_val_is_in(body["permission_names"], applicable_perm,
                              msg="Permission applied to anonymous group which user is member of should be effective")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PUBLIC
    def test_GetUserServiceResourcePermission_InheritedPublic_ParentPermission(self):
        """
        Tests that validates that non-admin user can obtain some specific resource permission via anonymous group
        permission applied on a parent resource of the targeted resource that supports sub-tree inheritance.
        """
        # setup
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        parent_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=parent_id)
        applicable_perm = body["permission_names"][0]
        child_res_id = body["resource_id"]
        path = "groups/{}/resources/{}/permissions".format(get_constant("MAGPIE_ANONYMOUS_GROUP"), parent_id)
        resp = utils.test_request(self, "POST", path, json={"permission_name": applicable_perm})
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        # test
        path = "/users/{}/resources/{}/permissions?effective=true".format(self.test_user_name, child_res_id)
        resp = utils.test_request(self, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("permission_names", body)
        utils.check_val_is_in(body["permission_names"], applicable_perm,
                              msg="Permission applied to anonymous group which user is member of should be effective")

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers(self):
        body = utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_is_in("user_name", info)
        utils.check_val_type(info["user_name"], six.string_types)
        utils.check_val_is_in("email", info)
        utils.check_val_type(info["email"], six.string_types)
        utils.check_val_is_in("group_names", info)
        utils.check_val_type(info["group_names"], list)

        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(self.test_user_name, users)

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_InvalidParameters(self):
        utils.warn_version(self, "validate user creation inputs", "2.0.0", skip=True)
        data = {
            "user_name": self.test_user_name,
            "email": "{}@mail.com".format(self.test_user_name),
            "password": self.test_user_name,
            "group_name": self.test_group_name,
        }
        for code, variant in [
            (400, {"user_name": ""}),
            (400, {"user_name": "   "}),
            (400, {"user_name": "abc???def"}),
            (400, {"user_name": "abc/def"}),
            (400, {"user_name": "A" * 1024}),
            (400, {"email": ""}),
            (400, {"email": "   "}),
            (400, {"email": "abc???def"}),
            (400, {"email": "abc/def"}),
            (400, {"email": "abc-def @ gmail dot com"}),
            (400, {"password": ""}),
            (400, {"password": "   "}),
            (400, {"group_name": "!ABC!"}),
            (404, {"group_name": ""}),
        ]:
            var_data = deepcopy(data).update(variant)
            resp = utils.test_request(self, "POST", "/users", json=var_data, expect_errors=True,
                                      headers=self.json_headers, cookies=self.cookies)
            utils.check_response_basic_info(resp, code, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_NoGroupParam_DefaultsAnonymous(self):
        """
        Validate that user created with non-special keyword group also becomes a member of ``MAGPIE_ANONYMOUS_GROUP``
        to ensure he will have access to publicly available resources.
        """
        utils.warn_version(self, "user creation without group parameter", "2.0.0", skip=True)
        data = {"user_name": self.test_user_name}  # no group
        utils.TestSetup.create_TestUser(self, override_data=data)
        utils.TestSetup.check_UserGroupMembership(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_AutoMemberships(self):
        """
        Validate that user created with non-special keyword group also becomes a member of ``MAGPIE_ANONYMOUS_GROUP``
        to ensure he will have access to publicly available resources.
        """
        new_test_group = "test-group-{}".format(self._testMethodName)  # noqa
        self.extra_group_names.append(new_test_group)
        utils.TestSetup.delete_TestGroup(self, override_group_name=new_test_group)  # if previous run
        utils.TestSetup.create_TestGroup(self, override_group_name=new_test_group)
        data = {"group_name": new_test_group}
        utils.TestSetup.create_TestUser(self, override_data=data)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_PostUsers_ReservedKeyword_Current(self):
        data = {
            "user_name": get_constant("MAGPIE_LOGGED_USER"),
            "password": "pwd",
            "email": "email@mail.com",
            "group_name": self.test_group_name,
        }
        resp = utils.test_request(self, "POST", "/users", data=data,
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_PatchUser_ReservedKeyword_Current(self):
        utils.warn_version(self, "user update own information ", "2.0.0", older=True, skip=True)
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        path = "/users/{usr}".format(usr=get_constant("MAGPIE_LOGGED_USER"))
        new_user_name = self.test_user_name + "-new-put-over-current"
        self.extra_user_names.append(new_user_name)
        data = {"user_name": new_user_name}
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method=self.update_method)

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_nothing(self):
        utils.TestSetup.create_TestUser(self, override_data={})
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data={},
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method=self.update_method)

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_username(self):
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        new_name = self.test_user_name + "-new"
        self.extra_user_names.append(new_name)

        # cleanup in case the updated username already exists (ex: previous test execution failure)
        utils.TestSetup.delete_TestUser(self, override_user_name=new_name)

        # update existing user name
        data = {"user_name": new_name}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)

        # validate change of user name
        path = "/users/{usr}".format(usr=new_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], new_name)

        # validate removed previous user name
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method="GET")

        # validate effective new user name
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(self, username=new_name, password=self.test_user_name,
                                                         use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], new_name)

        # validate ineffective previous user name
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=self.test_user_name, version=self.version,
            use_ui_form_submit=True, expect_errors=True)
        utils.check_val_equal(cookies, {}, msg="CookiesType should be empty from login failure.")
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_PatchUser_username_ReservedKeyword_Current(self):
        """Even administrator level user is not allowed to update any user name to reserved keyword."""
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        data = {"user_name": get_constant("MAGPIE_LOGGED_USER")}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_email(self):
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        new_email = "toto@new-email.lol"
        data = {"email": new_email}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)

        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["email"], new_email)

    @runner.MAGPIE_TEST_USERS
    def test_PatchUsers_password(self):
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        old_password = self.test_user_name
        new_password = "n0t-SO-ez-2-Cr4cK"  # nosec
        data = {"password": new_password}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)
        utils.check_or_try_logout_user(self)

        # validate that the new password is effective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=new_password,
            use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)
        utils.check_or_try_logout_user(self)

        # validate that previous password is ineffective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=old_password, version=self.version,
            use_ui_form_submit=True, expect_errors=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)

    @runner.MAGPIE_TEST_USERS
    def test_GetUser_existing(self):
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_is_in("user_name", info)
        utils.check_val_type(info["user_name"], six.string_types)
        utils.check_val_is_in("email", info)
        utils.check_val_type(info["email"], six.string_types)
        utils.check_val_is_in("group_names", info)
        utils.check_val_type(info["group_names"], list)

    @runner.MAGPIE_TEST_USERS
    def test_GetUser_missing(self):
        utils.TestSetup.check_NonExistingTestUser(self)
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers,
                                  cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method="GET")

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_ValidateDefaultGroups(self):
        resp = utils.test_request(self, "GET", "/groups", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        groups = body["group_names"]
        utils.check_val_is_in(get_constant("MAGPIE_ANONYMOUS_GROUP"), groups)
        utils.check_val_is_in(get_constant("MAGPIE_USERS_GROUP"), groups)
        utils.check_val_is_in(get_constant("MAGPIE_ADMIN_GROUP"), groups)

    @runner.MAGPIE_TEST_GROUPS
    def test_PostUserGroup(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.assign_TestUserGroup(self)
        utils.TestSetup.check_UserGroupMembership(self)

    @runner.MAGPIE_TEST_GROUPS
    def test_PostUserGroup_not_found(self):
        path = "/users/{usr}/groups".format(usr=get_constant("MAGPIE_ADMIN_USER"))
        data = {"group_name": "not_found"}
        resp = utils.test_request(self, "POST", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 404, expected_method="POST")

    @runner.MAGPIE_TEST_GROUPS
    def test_PostUserGroup_conflict(self):
        path = "/users/{usr}/groups".format(usr=get_constant("MAGPIE_ADMIN_USER"))
        data = {"group_name": get_constant("MAGPIE_ADMIN_GROUP")}
        resp = utils.test_request(self, "POST", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 409, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_LOGGED
    def test_PostUserGroup_AllowAdmin_SelfAssignMembership(self):
        """
        Admin-level user is allowed to assign itself to any group.

        .. seealso::
            - :meth:`Interface_MagpieAPI_UsersAuth.test_PostUserGroup_Forbidden_SelfAssignMembership`
        """
        # logged admin user assigns itself to new test group
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.assign_TestUserGroup(self, override_user_name=self.usr)

        # new user assigned to admin-group by current admin-user, then that new-user self-assigns to test group
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.assign_TestUserGroup(self, override_group_name=self.grp)
        utils.check_or_try_logout_user(self)
        utils.check_or_try_login_user(self, username=self.test_user_name, password=self.test_user_name)
        utils.TestSetup.assign_TestUserGroup(self, override_user_name=self.test_user_name,
                                             override_headers=self.test_headers, override_cookies=self.test_cookies)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserGroups(self):
        users_group = get_constant("MAGPIE_USERS_GROUP")
        utils.TestSetup.create_TestUser(self, override_group_name=users_group)
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.assign_TestUserGroup(self)

        path = "/users/{usr}/groups".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers,
                                  cookies=self.cookies, expect_errors=True)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)
        expected_groups = {self.test_group_name, users_group}
        if LooseVersion(self.version) >= LooseVersion("1.4.0"):
            expected_groups.add(get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.check_all_equal(body["group_names"], expected_groups, any_order=True)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser(self):
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.TestSetup.check_NonExistingTestUser(self)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_DeleteUser_forbidden_ReservedKeyword_Anonymous(self):
        """Even administrator level user is not allowed to remove the special anonymous user."""
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(anonymous, users, msg="Anonymous user pre-requirement missing for test.")
        path = "/users/{}".format(anonymous)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(anonymous, users, msg="Anonymous special user should still exist.")

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_not_found(self):
        path = "/users/magpie-unittest-random-user"
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method="DELETE")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    def test_DeleteUserGroup(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.assign_TestUserGroup(self)
        path = "/users/{usr}/groups/{grp}".format(usr=self.test_user_name, grp=self.test_group_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")
        path = "/users/{usr}/groups".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_not_in(self.test_group_name, body["group_names"])
        path = "/groups/{grp}".format(grp=self.test_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_not_in(self.test_user_name, body["group"]["user_names"])
        utils.check_val_equal(body["group"]["member_count"], 0)
        utils.warn_version(self, "Member count invalid (always zero).", "0.10.0", skip=False)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    def test_DeleteUserGroup_Forbidden_Anonymous(self):
        """
        Nobody is allowed to remove anonymous group membership to ensure 'Public' resource permission remain coherent.
        """
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        path = "/users/{}/groups/{}".format(self.test_user_name, get_constant("MAGPIE_ANONYMOUS_GROUP"))
        resp = utils.test_request(self, "DELETE", path, data={}, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, expected_method="DELETE", expected_code=403)

        # validate unmodified membership with admin user
        utils.check_or_try_logout_user(self)
        utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.check_UserGroupMembership(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroups(self):
        utils.TestSetup.create_TestGroup(self)
        path = "/groups"
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        for group in [
            get_constant("MAGPIE_ADMIN_GROUP"),
            get_constant("MAGPIE_USERS_GROUP"),
            get_constant("MAGPIE_ANONYMOUS_GROUP"),
            self.test_group_name,
        ]:
            utils.check_val_is_in(group, body["group_names"])

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroup_admin(self):
        admin_grp = get_constant("MAGPIE_ADMIN_GROUP")
        admin_usr = get_constant("MAGPIE_ADMIN_USER")
        path = "/groups/{grp}".format(grp=admin_grp)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group", body)
        utils.check_val_is_in(admin_usr, body["group"]["user_names"],
                              msg="Admin user should be automatically assigned to administrator group.")

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroup_exists(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.assign_TestUserGroup(self)

        path = "/groups/{grp}".format(grp=self.test_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group", body)
        utils.check_val_type(body["group"], dict)
        utils.check_val_is_in("user_names", body["group"])
        utils.check_val_type(body["group"]["user_names"], list)
        utils.check_val_is_in(self.test_user_name, body["group"]["user_names"])
        utils.check_val_is_in("group_id", body["group"])
        utils.check_val_type(body["group"]["group_id"], int)
        utils.check_val_is_in("description", body["group"])
        utils.check_val_type(body["group"]["description"], utils.OptionalStringType)
        utils.check_val_is_in("group_name", body["group"])
        utils.check_val_type(body["group"]["group_name"], six.string_types)
        utils.check_val_is_in("member_count", body["group"])
        utils.check_val_type(body["group"]["member_count"], int)
        if LooseVersion(self.version) >= LooseVersion("0.10.0"):
            utils.check_val_equal(body["group"]["member_count"], 1)
        else:
            utils.warn_version(self, "Member count invalid (always zero).", "0.10.0", skip=False)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroup_count(self):
        utils.warn_version(self, "Member count invalid (always zero).", "0.10.0", skip=True)

        utils.TestSetup.create_TestGroup(self)
        path = "/groups/{grp}".format(grp=self.test_group_name)
        for i in range(0, 3):
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.check_val_equal(body["group"]["member_count"], i)
            user_name = "magpie-unittest-user-group-{}".format(i)
            self.extra_user_names.append(user_name)
            utils.TestSetup.delete_TestUser(self, override_user_name=user_name)  # clean other test runs
            utils.TestSetup.create_TestUser(self, override_user_name=user_name)
            utils.TestSetup.assign_TestUserGroup(self, override_user_name=user_name)
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.check_val_equal(body["group"]["member_count"], i + 1)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroup_not_found(self):
        path = "/groups/magpie-unittest-random-group"
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method="GET")

    @runner.MAGPIE_TEST_GROUPS
    def test_PostGroups(self):
        utils.TestSetup.delete_TestGroup(self)  # setup as required
        utils.TestSetup.create_TestGroup(self)  # actual test
        utils.TestSetup.delete_TestGroup(self)  # cleanup

    @runner.MAGPIE_TEST_GROUPS
    def test_PostGroups_conflict(self):
        utils.TestSetup.delete_TestGroup(self)
        utils.TestSetup.create_TestGroup(self)
        data = {"group_name": self.test_group_name}
        resp = utils.test_request(self, "POST", "/groups", data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 409, expected_method="POST")

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_DeleteGroup_forbidden_ReservedKeyword_Anonymous(self):
        """Even administrator level user is not allowed to remove the special keyword anonymous group."""
        anonymous = get_constant("MAGPIE_ANONYMOUS_GROUP")
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(anonymous, groups, msg="Anonymous group pre-requirement missing for test.")
        path = "/groups/{}".format(anonymous)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(anonymous, groups, msg="Anonymous special group should still exist.")

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_DeleteGroup_forbidden_ReservedKeyword_Admin(self):
        """Even administrator level user is not allowed to remove the special keyword admin group."""
        admins = get_constant("MAGPIE_ADMIN_GROUP")
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(admins, groups, msg="Admin group pre-requirement missing for test.")
        path = "/groups/{}".format(admins)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(admins, groups, msg="Admin special group should still exist.")

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupUsers(self):
        path = "/groups/{grp}/users".format(grp=get_constant("MAGPIE_ADMIN_GROUP"))
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_val_is_in(get_constant("MAGPIE_ADMIN_USER"), body["user_names"])
        utils.check_val_is_in(self.usr, body["user_names"])

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupUsers_not_found(self):
        fake_group = "magpie-unittest-random-group"
        utils.TestSetup.delete_TestGroup(self, override_group_name=fake_group)
        path = "/groups/{}/users".format(fake_group)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method="GET")

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupServices(self):
        path = "/groups/{grp}/services".format(grp=self.grp)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        services = body["services"]
        utils.check_val_type(services, dict)
        service_types = utils.get_service_types_for_version(self.version)
        # as of version 0.7.0, visible services depend on the connected user permissions,
        # so all services types not necessarily returned in the response
        if LooseVersion(self.version) < LooseVersion("0.7.0"):
            utils.check_all_equal(services.keys(), service_types, any_order=True)
        for svc_type in services:
            utils.check_val_is_in(svc_type, service_types)  # one of valid service types
            for svc in services[svc_type]:
                svc_dict = services[svc_type][svc]  # type: JSON
                utils.check_val_type(svc_dict, dict)
                utils.check_val_is_in("resource_id", svc_dict)
                utils.check_val_is_in("service_name", svc_dict)
                utils.check_val_is_in("service_type", svc_dict)
                utils.check_val_is_in("public_url", svc_dict)
                utils.check_val_is_in("permission_names", svc_dict)
                utils.check_val_type(svc_dict["resource_id"], int)
                utils.check_val_type(svc_dict["service_name"], six.string_types)
                utils.check_val_type(svc_dict["service_type"], six.string_types)
                utils.check_val_type(svc_dict["public_url"], six.string_types)
                utils.check_val_type(svc_dict["permission_names"], list)
                if LooseVersion(self.version) >= LooseVersion("0.7.0"):
                    utils.check_val_is_in("service_sync_type", svc_dict)
                    utils.check_val_type(svc_dict["service_sync_type"], utils.OptionalStringType)
                    utils.check_val_not_in("service_url", svc_dict)
                else:
                    utils.check_val_is_in("service_url", svc_dict)
                    utils.check_val_type(svc_dict["service_url"], six.string_types)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupServiceResources(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        path = "/groups/{grp}/services/{svc}/resources".format(grp=self.grp, svc=self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("service", body)
        svc_dict = body["service"]
        utils.check_val_type(svc_dict, dict)
        utils.check_val_is_in("resource_id", svc_dict)
        utils.check_val_is_in("service_name", svc_dict)
        utils.check_val_is_in("service_type", svc_dict)
        utils.check_val_is_in("public_url", svc_dict)
        utils.check_val_is_in("permission_names", svc_dict)
        utils.check_val_is_in("resources", svc_dict)
        utils.check_val_type(svc_dict["resource_id"], int)
        utils.check_val_type(svc_dict["service_name"], six.string_types)
        utils.check_val_type(svc_dict["service_type"], six.string_types)
        utils.check_val_type(svc_dict["public_url"], six.string_types)
        utils.check_val_type(svc_dict["permission_names"], list)
        utils.check_val_type(svc_dict["resources"], dict)
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", svc_dict)
            utils.check_val_type(svc_dict["service_sync_type"], utils.OptionalStringType)
            utils.check_val_not_in("service_url", svc_dict)
        else:
            utils.check_val_is_in("service_url", svc_dict)
            utils.check_val_type(svc_dict["service_url"], six.string_types)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServices_ResponseFormat(self):
        utils.TestSetup.create_TestService(self)
        resp = utils.test_request(self, "GET", "/services", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("service", body)
        utils.check_val_type(body["services"], dict)
        service_types = utils.get_service_types_for_version(self.version)
        utils.check_all_equal(body["services"], service_types)
        for svc_type in body["services"]:
            for svc_name in body["services"][svc_type]:
                svc_info = body["services"][svc_type][svc_name]
                utils.check_val_not_in("resources", svc_info,
                                       msg="Must only provide summary details, not full resource tree.")
                utils.check_val_is_in("resource_id", body["service"])
                utils.check_val_is_in("public_url", body["service"])
                utils.check_val_is_in("service_url", body["service"])
                utils.check_val_is_in("service_name", body["service"])
                utils.check_val_is_in("service_type", body["service"])
                utils.check_val_is_in("permission_names", body["service"])
                utils.check_val_type(body["service"]["resource_id"], int)
                utils.check_val_type(body["service"]["public_url"], six.string_types)
                utils.check_val_type(body["service"]["service_url"], six.string_types)
                utils.check_val_type(body["service"]["service_name"], six.string_types)
                utils.check_val_type(body["service"]["service_type"], six.string_types)
                utils.check_val_type(body["service"]["permission_names"], list)
                utils.check_val_not_equal(len(body["service"]["permission_names"]), 0)
                if LooseVersion(self.version) >= LooseVersion("0.7.0"):
                    utils.check_val_is_in("service_sync_type", body["service"])
                    utils.check_val_type(body["service"]["service_sync_type"], utils.OptionalStringType)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServices_ResponseFormat(self):
        utils.warn_version(self, "Service listing as object list with query parameter", "2.0.0", skip=True)

        resp = utils.test_request(self, "GET", "/services", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        svc_name_total = 0
        for svc_type in body["services"]:
            for svc_name in body["services"][svc_type]:
                svc_name_total += 1

        resp = utils.test_request(self, "GET", "/services?list=true", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], list)
        utils.check_val_equal(len(body["services"]), svc_name_total)
        for svc_info in body["services"]:
            utils.check_val_type(svc_info, dict)
            utils.check_val_not_in("resources", svc_info,
                                   msg="Must only provide summary details, not full resource tree.")
            utils.check_val_is_in("resource_id", body["service"])
            utils.check_val_is_in("public_url", body["service"])
            utils.check_val_is_in("service_url", body["service"])
            utils.check_val_is_in("service_name", body["service"])
            utils.check_val_is_in("service_type", body["service"])
            utils.check_val_is_in("permission_names", body["service"])
            utils.check_val_type(body["service"]["resource_id"], int)
            utils.check_val_type(body["service"]["public_url"], six.string_types)
            utils.check_val_type(body["service"]["service_url"], six.string_types)
            utils.check_val_type(body["service"]["service_name"], six.string_types)
            utils.check_val_type(body["service"]["service_type"], six.string_types)
            utils.check_val_type(body["service"]["service_sync_type"], utils.OptionalStringType)
            utils.check_val_type(body["service"]["permission_names"], list)
            utils.check_val_not_equal(len(body["service"]["permission_names"]), 0)

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServices_ResponseFormat(self):
        body = utils.TestSetup.create_TestService(self)
        utils.check_val_is_in("service", body)
        utils.check_val_type(body["service"], dict)
        utils.check_val_not_in("resources", body, msg="Must only provide summary details, not full resource tree.")
        utils.check_val_is_in("resource_id", body["service"])
        utils.check_val_is_in("public_url", body["service"])
        utils.check_val_is_in("service_url", body["service"])
        utils.check_val_is_in("service_name", body["service"])
        utils.check_val_is_in("service_type", body["service"])
        utils.check_val_is_in("permission_names", body["service"])
        utils.check_val_type(body["service"]["resource_id"], int)
        utils.check_val_type(body["service"]["public_url"], six.string_types)
        utils.check_val_type(body["service"]["service_url"], six.string_types)
        utils.check_val_type(body["service"]["service_name"], six.string_types)
        utils.check_val_type(body["service"]["service_type"], six.string_types)
        utils.check_val_type(body["service"]["permission_names"], list)
        utils.check_val_not_equal(len(body["service"]["permission_names"]), 0)
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", body["service"])
            utils.check_val_type(body["service"]["service_sync_type"], utils.OptionalStringType)

    @runner.MAGPIE_TEST_SERVICES
    def test_PatchService_UpdateSuccess(self):
        body = utils.TestSetup.create_TestService(self)
        service = body["service"]
        new_svc_name = str(service["service_name"]) + "-updated"
        new_svc_url = str(service["service_url"]) + "/updated"
        self.extra_service_names.append(new_svc_name)
        utils.TestSetup.delete_TestService(self, override_service_name=new_svc_name)
        path = "/services/{svc}".format(svc=service["service_name"])
        data = {"service_name": new_svc_name, "service_url": new_svc_url}
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, expected_method=self.update_method)
        utils.check_val_is_in("service", body)
        utils.check_val_type(body["service"], dict)
        utils.check_val_not_in("resources", body, msg="Must only provide summary details, not full resource tree.")
        utils.check_val_is_in("resource_id", body["service"])
        utils.check_val_is_in("public_url", body["service"])
        utils.check_val_is_in("service_url", body["service"])
        utils.check_val_is_in("service_name", body["service"])
        utils.check_val_is_in("service_type", body["service"])
        utils.check_val_is_in("permission_names", body["service"])
        utils.check_val_type(body["service"]["resource_id"], int)
        utils.check_val_type(body["service"]["public_url"], six.string_types)
        utils.check_val_type(body["service"]["service_url"], six.string_types)
        utils.check_val_type(body["service"]["service_name"], six.string_types)
        utils.check_val_type(body["service"]["service_type"], six.string_types)
        utils.check_val_type(body["service"]["permission_names"], list)
        utils.check_val_not_equal(len(body["service"]["permission_names"]), 0)
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", body["service"])
            utils.check_val_type(body["service"]["service_sync_type"], utils.OptionalStringType)
        utils.check_val_equal(body["service"]["service_url"], new_svc_url)
        utils.check_val_equal(body["service"]["service_name"], new_svc_name)

    @runner.MAGPIE_TEST_SERVICES
    def test_PatchService_UpdateConflict(self):
        body = utils.TestSetup.create_TestService(self)
        service = body["service"]
        new_svc_name = str(service["service_name"]) + "-updated"
        new_svc_url = str(service["service_url"]) + "/updated"
        self.extra_service_names.append(new_svc_name)
        try:
            utils.TestSetup.create_TestService(self, override_service_name=new_svc_name)
            path = "/services/{svc}".format(svc=service["service_name"])
            data = {"service_name": new_svc_name, "service_url": new_svc_url}
            resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                      headers=self.json_headers, cookies=self.cookies)
            utils.check_response_basic_info(resp, 409, expected_method=self.update_method)
        finally:
            utils.TestSetup.delete_TestService(self, override_service_name=new_svc_name)

    @runner.MAGPIE_TEST_SERVICES
    def test_PatchService_NoUpdateInfo(self):
        # no path PATCH on '/services/types' (not equivalent to '/services/{service_name}')
        # so not even a forbidden case to handle
        resp = utils.test_request(self, self.update_method, "/services/types", data={}, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        if LooseVersion(self.version) >= LooseVersion("0.9.5"):
            # directly interpreted as expected path `/services/types` behaviour, so method PATCH not allowed
            utils.check_response_basic_info(resp, 405, expected_method=self.update_method)
        else:
            # no path with service named 'types', filtered as not found
            utils.check_response_basic_info(resp, 404, expected_method=self.update_method)

    @runner.MAGPIE_TEST_SERVICES
    def test_PatchService_ReservedKeyword_Types(self):
        # try to PATCH on 'types' path should raise the error
        data = {"service_name": "dummy", "service_url": "dummy"}
        resp = utils.test_request(self, self.update_method, "/services/types", data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        if LooseVersion(self.version) >= LooseVersion("0.9.5"):
            # directly interpreted as expected path `/services/types` behaviour, so method PUT not allowed
            utils.check_response_basic_info(resp, 405, expected_method=self.update_method)
        else:
            # no path with service named 'types', filtered as not found
            utils.check_response_basic_info(resp, 404, expected_method=self.update_method)

        utils.warn_version(self, "check for update service named 'types'", "0.9.1", skip=True)
        # try to PUT on valid service with new name 'types' should raise the error
        utils.TestSetup.create_TestService(self)
        path = "/services/{}".format(self.test_service_name)
        data = {"service_name": "types"}
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 400, expected_method=self.update_method)  # forbidden name 'types'
        utils.check_val_equal(body["detail"], s.Service_PATCH_BadRequestResponseSchema_ReservedKeyword.description)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetService_ResponseFormat(self):
        utils.TestSetup.create_TestService(self)
        path = "/services/{svc}".format(svc=self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        if LooseVersion(self.version) < LooseVersion("0.9.1"):
            utils.check_val_is_in(self.test_service_name, body)
            svc_info = body[self.test_service_name]
            utils.check_val_type(svc_info, dict)
        else:
            utils.check_val_is_in("service", body)
            svc_info = body["service"]
            utils.check_val_type(svc_info, dict)
            utils.check_val_is_in("resource_child_allowed", svc_info)
            utils.check_val_is_in("resource_types_allowed", svc_info)
            utils.check_val_type(svc_info["resource_child_allowed"], bool)
            utils.check_val_type(svc_info["resource_types_allowed"], list)
            if svc_info["resource_child_allowed"]:
                svc_type = svc_info["service_type"]
                allowed_res_type_names = SERVICE_TYPE_DICT[svc_type].resource_type_names
                utils.check_all_equal(svc_info["resource_types_allowed"], allowed_res_type_names)
            else:
                utils.check_val_equal(len(svc_info["resource_types_allowed"]), 0)
        utils.check_val_not_in("resources", svc_info, msg="Must only provide summary details, not full resource tree.")
        utils.check_val_is_in("resource_id", svc_info)
        utils.check_val_is_in("service_name", svc_info)
        utils.check_val_is_in("service_type", svc_info)
        utils.check_val_is_in("public_url", svc_info)
        utils.check_val_is_in("permission_names", svc_info)
        utils.check_val_type(svc_info["resource_id"], int)
        utils.check_val_type(svc_info["service_name"], six.string_types)
        utils.check_val_type(svc_info["service_type"], six.string_types)
        utils.check_val_type(svc_info["public_url"], six.string_types)
        utils.check_val_type(svc_info["permission_names"], list)
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", svc_info)
            utils.check_val_type(svc_info["service_sync_type"], utils.OptionalStringType)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServiceTypes_ResponseFormat(self):
        utils.warn_version(self, "get service types", "0.9.1", skip=True)

        resp = utils.test_request(self, "GET", "/services/types", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("service_types", body)
        utils.check_val_type(body["service_types"], list)
        utils.check_all_equal(body["service_types"], list(SERVICE_TYPE_DICT.keys()), any_order=True)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServiceTypeResources_ResponseFormat(self):
        utils.warn_version(self, "get service type resources", "0.9.1", skip=True)

        utils.TestSetup.create_TestService(self)
        path = "/services/types/{svc_type}/resources".format(svc_type=self.test_service_type)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("resource_types", body)
        utils.check_val_type(body["resource_types"], list)
        utils.check_val_equal(len(body["resource_types"]) > 0, True)
        for rt in body["resource_types"]:  # type: JSON
            utils.check_val_type(rt, dict)
            utils.check_val_is_in("resource_type", rt)
            utils.check_val_is_in("resource_child_allowed", rt)
            utils.check_val_is_in("permission_names", rt)
            utils.check_val_type(rt["resource_type"], six.string_types)
            utils.check_val_type(rt["resource_child_allowed"], bool)
            utils.check_val_type(rt["permission_names"], list)
            for p in rt["permission_names"]:
                utils.check_val_type(p, six.string_types)
            utils.check_val_is_in(rt["resource_type"], RESOURCE_TYPE_DICT)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServiceTypeResources_CheckValues(self):
        utils.warn_version(self, "get service type resources", "0.9.1", skip=True)

        # evaluate different types of services
        for svc_type, svc_res_info in [
            # recursive child resource allowed
            (ServiceAPI.service_type,
                {"route": {
                    "perms": [Permission.READ.value, Permission.WRITE.value,
                              Permission.READ_MATCH.value, Permission.WRITE_MATCH.value],
                    "child": True}}),
            # child resource allowed only for specific types
            (ServiceTHREDDS.service_type,
                {"directory": {
                    "perms": [Permission.READ.value, Permission.WRITE.value],
                    "child": True},
                 "file": {
                     "perms": [Permission.READ.value, Permission.WRITE.value],
                     "child": False}}),
            # no child allowed
            (ServiceAccess.service_type, {}),
        ]:
            # test response details
            path = "/services/types/{}/resources".format(svc_type)
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.check_val_type(body["resource_types"], list)
            utils.check_val_equal(len(body["resource_types"]), len(svc_res_info))
            for r in body["resource_types"]:  # type: JSON
                utils.check_val_is_in(r["resource_type"], svc_res_info)
                r_type = svc_res_info[r["resource_type"]]
                utils.check_val_equal(r["resource_child_allowed"], r_type["child"])
                utils.check_all_equal(r["permission_names"], r_type["perms"], any_order=True)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServiceResources(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        path = "/services/{svc}/resources".format(svc=self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        svc_dict = body[self.test_service_name]
        utils.check_val_is_in(self.test_service_name, body)
        utils.check_val_type(body[self.test_service_name], dict)
        utils.check_val_is_in("resource_id", svc_dict)
        utils.check_val_is_in("service_name", svc_dict)
        utils.check_val_is_in("service_type", svc_dict)
        utils.check_val_is_in("service_url", svc_dict)
        utils.check_val_is_in("public_url", svc_dict)
        utils.check_val_is_in("permission_names", svc_dict)
        utils.check_val_is_in("resources", svc_dict)
        utils.check_val_type(svc_dict["resource_id"], int)
        utils.check_val_type(svc_dict["service_name"], six.string_types)
        utils.check_val_type(svc_dict["service_url"], six.string_types)
        utils.check_val_type(svc_dict["service_type"], six.string_types)
        utils.check_val_type(svc_dict["public_url"], six.string_types)
        utils.check_val_type(svc_dict["permission_names"], list)
        utils.check_resource_children(svc_dict["resources"], svc_dict["resource_id"], svc_dict["resource_id"])
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", svc_dict)
            utils.check_val_type(svc_dict["service_sync_type"], utils.OptionalStringType)
        # FIXME: there must always be applicable permissions for Service route
        if LooseVersion(self.version) >= LooseVersion("2.0.0"):
            utils.check_val_not_equal(len(svc_dict["permission_names"]), 0,
                                      msg="Non user-scoped service route must always provide applicable permissions.")
            service_perms = [p.value for p in SERVICE_TYPE_DICT[svc_dict["service_type"]].permissions]
            utils.check_all_equal(svc_dict["permission_names"], service_perms, any_order=True)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServicePermissions(self):
        services_list = utils.TestSetup.get_RegisteredServicesList(self)

        for svc in services_list:
            svc_name = svc["service_name"]
            service_perms = [p.value for p in SERVICE_TYPE_DICT[svc["service_type"]].permissions]
            path = "/services/{svc}/permissions".format(svc=svc_name)
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.check_val_is_in("permission_names", body)
            utils.check_val_type(body["permission_names"], list)
            utils.check_all_equal(body["permission_names"], service_perms, any_order=True)

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServiceResources_DirectResource_NoParentID(self):
        utils.TestSetup.create_TestService(self)
        resources_prior = utils.TestSetup.get_TestServiceDirectResources(self)
        resources_prior_ids = [res["resource_id"] for res in resources_prior]
        body = utils.TestSetup.create_TestServiceResource(self)
        body = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.check_val_is_in("resource_id", body)
        utils.check_val_is_in("resource_name", body)
        utils.check_val_is_in("resource_type", body)
        utils.check_val_not_in(body["resource_id"], resources_prior_ids)
        utils.check_val_equal(body["resource_name"], self.test_resource_name)
        utils.check_val_equal(body["resource_type"], self.test_resource_type)

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServiceResources_DirectResource_WithParentID(self):
        utils.TestSetup.create_TestService(self)
        resources_prior = utils.TestSetup.get_TestServiceDirectResources(self)
        resources_prior_ids = [res["resource_id"] for res in resources_prior]
        service_id = utils.TestSetup.get_ExistingTestServiceInfo(self)["resource_id"]
        extra_data = {"parent_id": service_id}
        body = utils.TestSetup.create_TestServiceResource(self, extra_data)
        body = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.check_val_is_in("resource_id", body)
        utils.check_val_is_in("resource_name", body)
        utils.check_val_is_in("resource_type", body)
        utils.check_val_not_in(body["resource_id"], resources_prior_ids)
        utils.check_val_equal(body["resource_name"], self.test_resource_name)
        utils.check_val_equal(body["resource_type"], self.test_resource_type)

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServiceResources_ChildrenResource_ParentID(self):
        # create the direct resource
        body = utils.TestSetup.create_TestServiceResource(self)
        resources = utils.TestSetup.get_TestServiceDirectResources(self)
        resources_ids = [res["resource_id"] for res in resources]
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        test_resource_id = info["resource_id"]
        utils.check_val_is_in(test_resource_id, resources_ids,
                              msg="service resource must exist to create child resource")

        # create the child resource under the direct resource and validate response info
        child_resource_name = self.test_resource_name + "-children"
        override_data = {
            "resource_name": child_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": test_resource_id
        }
        body = utils.TestSetup.create_TestServiceResource(self, override_data=override_data)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.check_val_is_in("resource_id", info)
        utils.check_val_not_in(info["resource_id"], resources_ids)
        utils.check_val_is_in("resource_name", info)
        utils.check_val_equal(info["resource_name"], child_resource_name)
        utils.check_val_is_in("resource_type", info)
        utils.check_val_equal(info["resource_type"], self.test_resource_type)

        # validate created child resource info
        service_root_id = utils.TestSetup.get_ExistingTestServiceInfo(self)["resource_id"]
        child_resource_id = info["resource_id"]
        path = "/resources/{res_id}".format(res_id=child_resource_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        if LooseVersion(self.version) >= LooseVersion("0.9.2"):
            resource_body = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        else:
            utils.check_val_is_in(str(child_resource_id), body)
            resource_body = body[str(child_resource_id)]
        utils.check_val_equal(resource_body["root_service_id"], service_root_id)
        utils.check_val_equal(resource_body["parent_id"], test_resource_id)
        utils.check_val_equal(resource_body["resource_id"], child_resource_id)
        utils.check_val_equal(resource_body["resource_name"], child_resource_name)
        utils.check_val_equal(resource_body["resource_type"], self.test_resource_type)
        utils.check_val_type(resource_body["children"], dict)
        utils.check_val_equal(len(resource_body["children"]), 0)

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServiceResources_DirectResource_Conflict(self):
        utils.TestSetup.create_TestServiceResource(self)
        path = "/services/{svc}/resources".format(svc=self.test_service_name)
        data = {"resource_name": self.test_resource_name, "resource_type": self.test_resource_type}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers,
                                  cookies=self.cookies, json=data, expect_errors=True)
        body = utils.check_response_basic_info(resp, 409, expected_method="POST")
        utils.check_error_param_structure(body, version=self.version,
                                          is_param_value_literal_unicode=True, param_compare_exists=True,
                                          param_value=self.test_resource_name, param_name="resource_name")

    @runner.MAGPIE_TEST_SERVICES
    @runner.MAGPIE_TEST_DEFAULTS
    def test_ValidateDefaultServiceProviders(self):
        services_list = utils.TestSetup.get_RegisteredServicesList(self)

        # ensure that registered services information are all matching the providers in config file
        # ignore registered services not from providers as their are not explicitly required from the config
        for svc in services_list:
            svc_name = svc["service_name"]
            if svc_name in self.test_services_info:
                utils.check_val_equal(svc["service_type"], self.test_services_info[svc_name]["type"])
                hostname = utils.get_hostname(self)
                # private service URL should match format of Magpie (schema/host)
                svc_url = self.test_services_info[svc_name]["url"].replace("${HOSTNAME}", hostname)
                utils.check_val_equal(svc["service_url"], svc_url)
                # public service URL should match Twitcher config, but ignore schema that depends on each server config
                twitcher_svc_url = get_twitcher_protected_service_url(svc_name, hostname=hostname)
                twitcher_parsed_url = urlparse(twitcher_svc_url)
                twitcher_test_url = twitcher_parsed_url.netloc + twitcher_parsed_url.path
                svc_parsed_url = urlparse(svc["public_url"])
                svc_test_public_url = svc_parsed_url.netloc + svc_parsed_url.path
                utils.check_val_equal(svc_test_public_url, twitcher_test_url)

        # ensure that no providers are missing from registered services
        registered_svc_names = [svc["service_name"] for svc in services_list]
        for svc_name in self.test_services_info:
            utils.check_val_is_in(svc_name, registered_svc_names)

        # ensure that 'getcapabilities' permission is given to anonymous for applicable services
        # ignore extra services not in providers configuration that *could* be in the tested database
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        services_list_getcap = [svc for svc in services_list
                                if "getcapabilities" in svc["permission_names"]
                                and svc["service_name"] in self.test_services_info]
        path = "/users/{usr}/services".format(usr=anonymous)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        services_body = body["services"]  # type: JSON
        for svc in services_list_getcap:
            svc_name = svc["service_name"]
            svc_type = svc["service_type"]
            msg = "Service '{name}' of type '{type}' is expected to have '{perm}' permissions for user '{usr}'." \
                  .format(name=svc_name, type=svc_type, perm="getcapabilities", usr=anonymous)
            utils.check_val_is_in(svc_name, services_body[svc_type], msg=msg)
            utils.check_val_is_in("getcapabilities", services_body[svc_type][svc_name]["permission_names"])  # noqa

    @runner.MAGPIE_TEST_RESOURCES
    def test_PostResources_DirectServiceResource(self):
        utils.TestSetup.create_TestService(self)
        service_info = utils.TestSetup.get_ExistingTestServiceInfo(self)
        service_resource_id = service_info["resource_id"]

        data = {
            "resource_name": self.test_resource_name,
            "resource_display_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_resource_id
        }
        resp = utils.test_request(self, "POST", "/resources",
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        body = utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.check_post_resource_structure(body, self.test_resource_name, self.test_resource_type,
                                            self.test_resource_name, self.version)

    @runner.MAGPIE_TEST_RESOURCES
    def test_PostResources_DirectServiceResourceOptional(self):
        utils.TestSetup.create_TestService(self)
        service_info = utils.TestSetup.get_ExistingTestServiceInfo(self)
        service_resource_id = service_info["resource_id"]

        data = {
            "resource_name": self.test_resource_name,
            # resource_display_name should default to self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_resource_id
        }
        resp = utils.test_request(self, "POST", "/resources",
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        body = utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.check_post_resource_structure(body, self.test_resource_name, self.test_resource_type,
                                            self.test_resource_name, self.version)

    @runner.MAGPIE_TEST_RESOURCES
    def test_PostResources_ChildrenResource(self):
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        direct_resource_id = info["resource_id"]

        data = {
            "resource_name": self.test_resource_name,
            "resource_display_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": direct_resource_id
        }
        resp = utils.test_request(self, "POST", "/resources",
                                  headers=self.json_headers, cookies=self.cookies, data=data)
        body = utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.check_post_resource_structure(body, self.test_resource_name, self.test_resource_type,
                                            self.test_resource_name, self.version)

    @runner.MAGPIE_TEST_RESOURCES
    def test_PostResources_MissingParentID(self):
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = utils.test_request(self, "POST", "/resources",
                                  headers=self.json_headers, cookies=self.cookies, data=data, expect_errors=True)
        body = utils.check_response_basic_info(resp, 422, expected_method="POST")
        utils.check_error_param_structure(body, version=self.version,
                                          param_name="parent_id", param_value=repr(None))

    @runner.MAGPIE_TEST_RESOURCES
    def test_DeleteResource(self):
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        resource_id = info["resource_id"]

        path = "/resources/{res_id}".format(res_id=resource_id)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")
        utils.TestSetup.check_NonExistingTestServiceResource(self)


@runner.MAGPIE_TEST_UI
class Interface_MagpieUI_NoAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie UI. Test any operation that do not require user AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @runner.MAGPIE_TEST_STATUS
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/", expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/login", expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewUsers(self):
        utils.TestSetup.check_Unauthorized(self, method="GET", path="/ui/users", expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups(self):
        utils.TestSetup.check_Unauthorized(self, method="GET", path="/ui/groups", expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServices(self):
        utils.TestSetup.check_Unauthorized(self, method="GET", path="/ui/services/default",
                                           expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServicesOfType(self):
        path = "/ui/services/{}".format(self.test_service_type)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUser(self):
        path = "/ui/users/{}/default".format(self.test_user_name)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroup(self):
        path = "/ui/groups/{}/default".format(self.test_group_name)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditService(self):
        path = "/ui/services/{type}/{name}".format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_AddUser(self):
        path = "/ui/users/add"
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)
        utils.TestSetup.check_Unauthorized(self, method="POST", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_AddGroup(self):
        path = "/ui/groups/add"
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)
        utils.TestSetup.check_Unauthorized(self, method="POST", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_AddService(self):
        path = "/ui/services/{}/add".format(self.test_service_type)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)
        utils.TestSetup.check_Unauthorized(self, method="POST", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewUserAccount(self):
        path = "/ui/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)
        utils.TestSetup.check_Unauthorized(self, method="POST", path=path, expected_type=CONTENT_TYPE_HTML)


@runner.MAGPIE_TEST_UI
class Interface_MagpieUI_UsersAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase, User_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie UI. Test any operation that require at least logged user AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    def __init__(self, *args, **kwargs):
        super(Interface_MagpieUI_UsersAuth, self).__init__(*args, **kwargs)
        self.magpie_title = "Magpie User Management"

    def setUp(self):
        User_Magpie_TestCase.setUp(self)

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd)
        assert headers and cookies, cls.require             # nosec
        assert cls.headers and cls.cookies, cls.require     # nosec

    @runner.MAGPIE_TEST_LOGIN
    def test_FormLogin(self):
        utils.check_or_try_logout_user(self)
        resp = utils.test_request(self, "GET", "/session", headers=self.test_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_equal(body["authenticated"], False)

        header, cookies = utils.check_or_try_login_user(self, use_ui_form_submit=True,
                                                        username=self.test_user_name, password=self.test_user_name)
        resp = utils.test_request(self, "GET", "/session", headers=header, cookies=cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_UserAccount_ViewDetails(self):
        """Logged user can view its own details on account page."""
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        resp = utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/users/current")
        utils.check_val_is_in("Account User", resp.text)
        utils.check_val_is_in(self.test_user_name, resp.text)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_UserAccount_ViewDiscoverableGroupsMembership(self):
        """Logged user can view discoverable groups and which ones he has membership on."""
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        resp = utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/users/current")
        utils.check_val_is_in("Account User", resp.text)
        utils.check_val_is_in(self.test_user_name, resp.text)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_UserAccount_UpdateDetails_email(self):
        """Logged user can update its own email on account page."""
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        data = {"new_user_email": "new-mail@unittest-mail.com"}
        resp = utils.TestSetup.check_FormSubmit(self, form_match="edit_email", form_data=data, form_submit="edit_email",
                                                method="GET", path="/ui/users/current")
        utils.check_ui_response_basic_info(resp, expected_title="Magpie user Management")
        resp = utils.test_request(self, "GET", "/users/current", headers=self.json_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["email"], data["new_user_email"])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_UserAccount_UpdateDetails_password(self):
        """Logged user can update its own password on account page."""
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        data = {"new_user_password": "123456"}
        # trigger the edit button form to obtain the 1st response with input field, then submit 2nd form with new value
        resp = utils.TestSetup.check_FormSubmit(self, form_match="edit_password", form_data={"edit_password": True},
                                                form_submit="edit_password", method="GET", path="/ui/users/current")
        resp = utils.TestSetup.check_FormSubmit(self, form_match="edit_password", form_data=data,
                                                form_submit="save_password", previous_response=resp)
        utils.check_ui_response_basic_info(resp, expected_title="Magpie user Management")
        # cannot check modified password value directly (because regenerated hash), therefore validate login with it
        utils.check_or_try_logout_user(self)
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  data={"user_name": self.test_user_name, "password": data["new_user_password"]})
        utils.check_response_basic_info(resp, 200, expected_method="POST")
        # verify that old password does not work anymore
        utils.check_or_try_logout_user(self)
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={}, expect_errors=True,
                                  data={"user_name": self.test_user_name, "password": self.test_user_name})
        utils.check_response_basic_info(resp, 401, expected_method="POST")


@runner.MAGPIE_TEST_UI
class Interface_MagpieUI_AdminAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie UI. Test any operation that require at least 'administrator' group
    AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def check_requirements(cls):
        headers, cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd)
        assert headers and cookies, cls.require             # nosec
        assert cls.headers and cls.cookies, cls.require     # nosec

    @runner.MAGPIE_TEST_STATUS
    def test_Home(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/")

    @runner.MAGPIE_TEST_STATUS
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/login")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewUsers(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/users")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewUsers_Goto_EditUser(self):
        form = {"edit": None, "user_name": self.test_user_name}
        form_name = "edit_username" if LooseVersion(self.version) >= LooseVersion("2.0.0") else "edit"
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit=form_name, path="/ui/users")
        if LooseVersion(self.version) < "2":
            test = "Edit User: {}".format(self.test_user_name)
        else:
            test = "Edit User: [{}]".format(self.test_user_name)
        utils.check_val_is_in(test, resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/groups")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups_Goto_EditGroup(self):
        form = {"edit": None, "group_name": self.test_group_name}
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path="/ui/groups")
        if LooseVersion(self.version) < "2":
            test = "Edit Group: {}".format(self.test_group_name)
        else:
            test = "Edit Group: [{}]".format(self.test_group_name)
        utils.check_val_is_in(test, resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServicesDefault(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/services/default")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServicesOfType(self):
        path = "/ui/services/{}".format(self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServices_Goto_EditService(self):
        form = {"edit": None, "service_name": self.test_service_name}
        path = "/ui/services/{}".format(self.test_service_type)
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path=path)
        find = "<span class=\"panel-value\">{}</span>".format(self.test_service_name)
        utils.check_val_is_in(find, resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUser(self):
        path = "/ui/users/{}/default".format(self.test_user_name)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUserService(self):
        path = "/ui/users/{usr}/{type}".format(usr=self.test_user_name, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroup(self):
        path = "/ui/groups/{}/default".format(self.test_group_name)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroupService(self):
        path = "/ui/groups/{grp}/{type}".format(grp=self.test_group_name, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditService(self):
        path = "/ui/services/{type}/{name}".format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_AddUser(self):
        path = "/ui/users/add"
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)
        # empty fields, same page but with 'incorrect' indicator due to invalid form inputs
        utils.TestSetup.check_UpStatus(self, method="POST", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_AddGroup(self):
        path = "/ui/groups/add"
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)
        # empty fields, same page but with 'incorrect' indicator due to invalid form inputs
        utils.TestSetup.check_UpStatus(self, method="POST", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_AddService(self):
        path = "/ui/services/{}/add".format(self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)
        # empty fields, same page but with 'incorrect' indicator due to invalid form inputs
        utils.TestSetup.check_UpStatus(self, method="POST", path=path, expected_type=CONTENT_TYPE_HTML)
