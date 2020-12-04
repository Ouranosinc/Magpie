import os
import unittest
import warnings
from abc import ABCMeta, abstractmethod
from copy import deepcopy
from typing import TYPE_CHECKING

import mock
import pyramid.testing
import six
import yaml
from pyramid.interfaces import IRequestExtensions
from six.moves.urllib.parse import urlparse

from magpie.adapter import MagpieAdapter
from magpie.api import schemas as s
from magpie.constants import MAGPIE_ROOT, get_constant
from magpie.models import RESOURCE_TYPE_DICT, Directory, Route
from magpie.permissions import Access, Permission, PermissionSet, PermissionType, Scope
from magpie.register import pseudo_random_string
from magpie.services import SERVICE_TYPE_DICT, ServiceAccess, ServiceAPI, ServiceNCWMS2, ServiceTHREDDS
from magpie.utils import CONTENT_TYPE_HTML, CONTENT_TYPE_JSON, CONTENT_TYPE_TXT_XML, get_twitcher_protected_service_url
from tests import runner, utils
from tests.utils import TestVersion

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, List, Optional, Set, Union

    from sqlalchemy.orm.session import Session
    from webtest.app import TestApp

    from magpie.typedefs import JSON, CookiesType, HeadersType, Str


@six.add_metaclass(ABCMeta)
class BaseTestCase(unittest.TestCase):
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
    version = None                  # type: Optional[Str]
    require = None                  # type: Optional[Str]
    url = None                      # type: Optional[Str]
    app = None                      # type: Optional[TestApp]
    test_app = None                 # type: Optional[TestApp]
    # parameters for setup operations, admin-level access to the app
    grp = None                      # type: Optional[Str]
    usr = None                      # type: Optional[Str]
    pwd = None                      # type: Optional[Str]
    cookies = None                  # type: Optional[CookiesType]
    headers = None                  # type: Optional[HeadersType]
    json_headers = {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON}
    test_headers = None             # type: Optional[HeadersType]
    test_cookies = None             # type: Optional[CookiesType]
    # parameters for testing, extracted automatically within 'utils.TestSetup' methods
    test_service_type = None        # type: Optional[Str]
    test_service_name = None        # type: Optional[Str]
    test_resource_name = None       # type: Optional[Str]
    test_resource_type = None       # type: Optional[Str]
    test_user_name = None           # type: Optional[Str]  # reuse as password to simplify calls when creating test user
    test_group_name = None          # type: Optional[Str]
    # extra parameters to indicate cleanup on final tear down
    # add new test values on test case startup before they *potentially* get interrupted because of error
    extra_user_names = set()        # type: Set[Str]
    extra_group_names = set()       # type: Set[Str]
    extra_resource_ids = set()      # type: Set[int]
    extra_service_names = set()     # type: Set[Str]

    # NOTE: don't forget to override this, or your specialized test-suite will not run
    __test__ = False    # won't run this as a test case, only its derived classes that overrides to True

    @classmethod
    @abstractmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        """
        Cleans up any left-over known object prefixed by ``test_`` as well as any other items added to sets prefixed by
        ``extra_``, in case some test failed to do so (e.g.: because it raised midway or was simply forgotten).
        """
        utils.check_or_try_logout_user(cls)
        admin_usr, admin_pwd = get_constant("MAGPIE_ADMIN_USER"), get_constant("MAGPIE_ADMIN_PASSWORD")
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls, username=admin_usr, password=admin_pwd)
        # remove test service/resource if overridden by test-case class implementers
        if cls.test_resource_name:
            utils.TestSetup.delete_TestServiceResource(cls)
        if cls.test_service_name:
            utils.TestSetup.delete_TestService(cls)
        # avoid attempt cleanup of reserved keyword user/group, since it will fail with magpie '>=2.x'
        reserved_users = [get_constant("MAGPIE_ADMIN_USER"), get_constant("MAGPIE_ANONYMOUS_USER")]
        reserved_groups = [get_constant("MAGPIE_ADMIN_GROUP"), get_constant("MAGPIE_ANONYMOUS_GROUP")]
        cls.extra_user_names.add(cls.test_user_name)
        cls.extra_group_names.add(cls.test_group_name)
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
        if TestVersion(self.version) >= TestVersion("2.0.0"):
            return "PATCH"
        return "PUT"

    @classmethod
    def setup_admin(cls):
        """
        Recreates the admin user employed for test data setup using the default Magpie administrator created at startup.

        Admin user is generated using (:attr:`BaseTestCase.usr`, :attr:`BaseTestCase.pwd`, :attr:`BaseTestCase.grp`).
        Skip the operation if those details correspond to the default Magpie administrator.
        """
        admin_grp = get_constant("MAGPIE_ADMIN_GROUP")
        admin_usr = get_constant("MAGPIE_ADMIN_USER")
        admin_pwd = get_constant("MAGPIE_ADMIN_PASSWORD")
        if not cls.usr:
            cls.usr = "unittest-admin"
        if not cls.pwd:
            cls.pwd = pseudo_random_string(20)
        if not cls.grp:
            cls.grp = admin_grp
        if cls.usr != admin_usr:
            utils.check_or_try_logout_user(cls)
            admin_headers, admin_cookies = utils.check_or_try_login_user(cls, username=admin_usr, password=admin_pwd,
                                                                         use_ui_form_submit=True)
            admin_headers.update(cls.json_headers)
            utils.TestSetup.delete_TestUser(cls, override_user_name=cls.usr,
                                            override_headers=admin_headers, override_cookies=admin_cookies)
            utils.TestSetup.create_TestUser(cls, override_user_name=cls.usr, override_password=cls.pwd,
                                            override_group_name=admin_grp,
                                            override_headers=admin_headers, override_cookies=admin_cookies)
            if cls.grp != admin_grp:
                utils.TestSetup.assign_TestUserGroup(cls, override_group_name=cls.grp, override_user_name=cls.usr,
                                                     override_headers=admin_headers, override_cookies=admin_cookies)
            utils.check_or_try_logout_user(cls)

    def setUp(self):
        self.test_app = None  # reset: each test must redefine it if a custom one is needed

    def tearDown(self):
        pass


@runner.MAGPIE_TEST_AUTH_PUBLIC
class NoAuthTestCase(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        super(NoAuthTestCase, cls).tearDownClass()

    def setUp(self):
        # validate on each new test-case that we are not logged in from invalid operation of some previous test
        utils.check_or_try_logout_user(self, msg="must be anonymous to evaluate this test case")

    def tearDown(self):
        super(NoAuthTestCase, self).tearDown()


class BaseAdminTestCase(BaseTestCase):
    """
    Extension of :class:`BaseTestCase` to handle test preparation/cleanup by administrator-level user.
    """
    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        super(BaseAdminTestCase, cls).tearDownClass()

    @classmethod
    def check_requirements(cls):
        utils.check_or_try_logout_user(cls)  # in case user changed during another test
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls, username=cls.usr, password=cls.pwd)
        assert cls.headers and cls.cookies, cls.require     # nosec
        cls.headers.update(cls.json_headers)

    def cleanup(self):
        """
        Removes test attributes from database to avoid conflict and unwanted behaviour due to previous definitions.

        Each employed test attribute must be overridden by the :attr:`setUpClass` of the `Test Case`.
        """
        self.check_requirements()  # re-login as needed in case test logged out the user with permissions
        if self.test_resource_name:
            utils.TestSetup.delete_TestServiceResource(self)
        if self.test_service_name:
            utils.TestSetup.delete_TestService(self)
        if self.test_user_name:
            utils.TestSetup.delete_TestUser(self)
        if self.test_group_name:
            utils.TestSetup.delete_TestGroup(self)

    def setUp(self):
        super(BaseAdminTestCase, self).setUp()
        self.cleanup()

    def tearDown(self):
        super(BaseAdminTestCase, self).tearDown()
        self.cleanup()


@runner.MAGPIE_TEST_AUTH_ADMIN
class AdminTestCase(BaseAdminTestCase):
    """
    Extension of :class:`BaseTestCase` for specific requirements to run administrator-level user operations.
    """
    @classmethod
    def setUpClass(cls):
        raise NotImplementedError


@runner.MAGPIE_TEST_AUTH_USERS
class UserTestCase(BaseAdminTestCase):
    """
    Extension of :class:`BaseTestCase` to handle another user session than the administrator-level user.

    Employs the admin-base to setup test-data, but afterward allows switching to the non-admin user to test operations.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):
        super(UserTestCase, cls).tearDownClass()

    def setUp(self):
        """
        Login as admin to setup test items from fresh start and remain logged in as admin since test cases might need to
        setup additional items. Each test **MUST** call :meth:`login_test_user` before testing when finished setup.

        Ensure that test user will have test group membership but not admin-level access.
        """
        super(UserTestCase, self).setUp()  # admin login and cleanup
        # setup minimal test user requirements
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        admin_group = get_constant("MAGPIE_ADMIN_GROUP")
        utils.TestSetup.check_UserGroupMembership(self, member=False, override_group_name=admin_group)
        utils.TestSetup.check_UserGroupMembership(self, member=True, override_group_name=self.test_group_name)

    def tearDown(self):
        utils.check_or_try_logout_user(self)

    def login_test_user(self):
        # type: () -> utils.OptionalHeaderCookiesType
        """
        Logs out any current user session and login the ``test_user_name`` instead.

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
            self, username=self.test_user_name, password=self.test_user_name, use_ui_form_submit=True)
        for header in ["Location", "Content-Type", "Content-Length"]:
            self.test_headers.pop(header, None)
        assert self.test_cookies, "Cannot test user-level access routes without logged user"
        return self.test_headers, self.test_cookies


@runner.MAGPIE_TEST_API
@six.add_metaclass(ABCMeta)
class Interface_MagpieAPI_NoAuth(NoAuthTestCase, BaseTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that do not require user AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

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

    @runner.MAGPIE_TEST_STATUS
    def test_NotAcceptableRequest(self):
        utils.warn_version(self, "Unsupported 'Accept' header returns 406 directly.", "0.10.0", skip=True)
        for path in ["/session", "/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))]:
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
        """
        Not logged-in user cannot update membership to group although group is discoverable.
        """
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        resp = utils.test_request(self, "GET", "/register/groups", headers=self.json_headers, expect_errors=True)
        body = utils.check_response_basic_info(resp, 401)
        utils.check_val_not_in("group_names", body)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_REGISTER
    def test_UnregisterDiscoverableGroup_Unauthorized(self):
        """
        Not logged-in user cannot remove membership to group although group is discoverable.
        """
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        path = "/register/groups/random-group"
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, 401, expected_method="DELETE")

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_REGISTER
    def test_ViewDiscoverableGroup_Unauthorized(self):
        """
        Not logged-in user cannot view group although group is discoverable.
        """
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        # login to setup test data
        utils.check_or_try_logout_user(self)
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        self.headers.update(self.json_headers)

        # setup some actual discoverable group to ensure the error is not caused by some misinterpreted response
        self.extra_group_names.add(self.test_group_name)
        group_data = {"group_name": self.test_group_name, "discoverable": True}
        utils.TestSetup.delete_TestGroup(self, override_group_name=self.test_group_name)
        utils.TestSetup.create_TestGroup(self, override_data=group_data)
        utils.check_or_try_logout_user(self)  # re-logout to test

        path = "/register/groups/{}".format(self.test_group_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, 401, expected_method="DELETE")

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_REGISTER
    def test_ListDiscoverableGroup_Unauthorized(self):
        """
        Not logged-in user cannot list group names although groups are discoverable.
        """
        utils.warn_version(self, "User registration views not yet available.", "2.0.0", skip=True)
        resp = utils.test_request(self, "GET", "/register/groups", headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, 401)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_STATUS
    def test_GetUser_ReservedKeyword_Anonymous_Allowed(self):
        """
        Not logged-in user is allowed to get information about unauthenticated user with explicit user-name.
        """
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        path = "/users/{}".format(anonymous)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers)
        body = utils.check_response_basic_info(resp)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], anonymous)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_STATUS
    def test_GetUser_ReservedKeyword_LoggedUser_InvalidNotGlobed(self):
        """
        Test that logged user special keyword with more characters doesn't get incorrectly interpreted.

        Older version bug would infer the logged user keyword although path variable was not *exactly* equal to it.
        """
        utils.warn_version(self, "validation of complete logged user keyword", "2.0.0", skip=True)
        path = "/users/{}{}".format(get_constant("MAGPIE_LOGGED_USER"), "extra")
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, 404)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_STATUS
    def test_GetUser_ReservedKeyword_LoggedUser_Allowed(self):
        """
        Not logged-in user is allowed to get information about unauthenticated user with implicit special keyword.
        """
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        path = "/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.test_request(self, "GET", path, headers=self.json_headers)
        body = utils.check_response_basic_info(resp)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], anonymous)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_STATUS
    def test_GetUser_OtherUser_Unauthorized(self):
        """
        Not logged-in user is not allowed to get information about any other user.
        """
        # login to setup test data, then re-logout to test
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        self.headers.update(self.json_headers)
        utils.TestSetup.delete_TestUser(self)
        body = utils.TestSetup.create_TestUser(self, override_group_name=None)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_or_try_logout_user(self)

        path = "/users/{}".format(info["user_name"])
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, expect_errors=True)
        utils.check_response_basic_info(resp, expected_code=401)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_STATUS
    def test_UpdateUser_ReservedKeyword_Anonymous_Unauthorized(self):
        """
        Not logged-in user is not allowed to update "own" information as it doesn't represent an actual user account.
        """
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        path = "/users/{}".format(anonymous)
        data = {"user_name": anonymous + "-updated-name"}
        resp = utils.test_request(self, self.update_method, path, json=data, expect_errors=True)
        utils.check_response_basic_info(resp, expected_code=401, expected_method=self.update_method)

        # login to validate user was not updated
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.get_UserInfo(self, override_username=anonymous)  # if found, no update was applied

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_STATUS
    def test_UpdateUser_ReservedKeyword_LoggedUser_Unauthorized(self):
        """
        Not logged-in user resolved via logged-user special keyword is not allowed to update "own" information as it
        does not correspond to an actual user account.
        """
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        logged = get_constant("MAGPIE_LOGGED_USER")
        path = "/users/{}".format(logged)
        data = {"user_name": logged + "-updated-name"}
        resp = utils.test_request(self, self.update_method, path, json=data, expect_errors=True)
        utils.check_response_basic_info(resp, expected_code=401, expected_method=self.update_method)

        # login to validate user was not updated (check explicit anonymous since logged-user points to it during update)
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.get_UserInfo(self, override_username=anonymous)  # if found, no update was applied

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_STATUS
    def test_UpdateUser_OtherUser_Unauthorized(self):
        # login to setup test data, then re-logout to test
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        self.headers.update(self.json_headers)
        utils.TestSetup.delete_TestUser(self)
        body = utils.TestSetup.create_TestUser(self, override_group_name=None)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_or_try_logout_user(self)

        path = "/users/{}".format(info["user_name"])
        new_user_name = "{}-updated-name".format(info["user_name"])
        self.extra_user_names.add(new_user_name)
        data = {"user_name": new_user_name}
        resp = utils.test_request(self, self.update_method, path, json=data, expect_errors=True)
        utils.check_response_basic_info(resp, expected_code=401, expected_method=self.update_method)

        # login to validate user was not updated
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.get_UserInfo(self, override_username=self.test_user_name)  # if found, no update was applied

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_STATUS
    def test_DeleteUser_ReservedKeyword_Anonymous_Unauthorized(self):
        """
        Not logged-in user is not allowed to delete his own account as it doesn't represent an actual user account.
        """
        anonymous = get_constant("MAGPIE_ANONYMOUS_USER")
        path = "/users/{}".format(anonymous)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True)
        utils.check_response_basic_info(resp, expected_code=401, expected_method="DELETE")

        # login to validate user was not updated
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.get_UserInfo(self, override_username=anonymous)  # if found, no update was applied

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_STATUS
    def test_DeleteUser_ReservedKeyword_Admin_Unauthorized(self):
        """
        Not logged-in user is not allowed to delete the special admin user.
        """
        admin = get_constant("MAGPIE_ADMIN_USER")
        path = "/users/{}".format(admin)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True)
        utils.check_response_basic_info(resp, expected_code=401, expected_method="DELETE")

        # login to validate user was not updated
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.get_UserInfo(self, override_username=admin)  # if found, no update was applied

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_STATUS
    def test_DeleteUser_OtherUser_Unauthorized(self):
        """
        Not logged-in user is not allowed to delete any other user.
        """
        # login to setup test data, then re-logout to test
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        self.headers.update(self.json_headers)
        utils.TestSetup.delete_TestUser(self)
        body = utils.TestSetup.create_TestUser(self, override_group_name=None)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_or_try_logout_user(self)

        path = "/users/{}".format(info["user_name"])
        resp = utils.test_request(self, "DELETE", path, expect_errors=True)
        utils.check_response_basic_info(resp, expected_code=401, expected_method="DELETE")

        # login to validate user was not updated
        self.headers, self.cookies = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.get_UserInfo(self, override_username=self.test_user_name)  # if found, no deletion was applied


@runner.MAGPIE_TEST_API
@six.add_metaclass(ABCMeta)
class Interface_MagpieAPI_UsersAuth(UserTestCase, BaseTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that require at least logged user AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.

    .. warning::
        After base setup completes, the remembered cookies are admin-level to allow setup of more specific test items
        per test case. It is necessary to call :meth:`login_test_user` after all setup data is completed in order to
        actually evaluate non-admin-level operations.

    .. seealso::
        - :meth:`UserTestCase.setUp`
        - :meth:`UserTestCase.login_test_user`
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    def login_test_user(self):
        """
        Apply JSON headers on top of login headers for API calls.
        """
        UserTestCase.login_test_user(self)
        self.test_headers.update(self.json_headers)
        return self.test_headers, self.test_cookies

    @runner.MAGPIE_TEST_LOGIN
    def test_PostSignin_EmailAsUsername(self):
        """
        User is allowed to use its email as username for login.
        """
        UserTestCase.login_test_user(self)
        info = utils.TestSetup.get_UserInfo(self,
                                            override_headers=self.test_headers,
                                            override_cookies=self.test_cookies)
        utils.check_val_is_in(self.test_user_name, info["email"])
        utils.check_or_try_logout_user(self)
        data = {"user_name": info["email"], "password": self.test_user_name}
        resp = utils.test_request(self, "POST", "/signin", data=data, headers=self.json_headers, cookies={})
        body = utils.check_response_basic_info(resp, expected_method="POST")
        utils.check_val_equal(body["detail"], s.Signin_POST_OkResponseSchema.description)

    @runner.MAGPIE_TEST_LOGIN
    def test_PostSignin_MissingCredentials(self):
        """
        Signin attempt with missing returns bad request, not internal server error nor.
        """
        # warn for new check, but don't skip lower version as it should work in previous releases
        utils.warn_version(self, "signin missing credentials field validation", "2.0.0", skip=False)
        utils.check_or_try_logout_user(self)

        data = {"user_name": self.usr}  # missing required password
        resp = utils.test_request(self, "POST", "/signin", data=data, expect_errors=True,
                                  headers=self.json_headers, cookies={})
        if TestVersion(self.version) >= TestVersion("3.0"):
            code = 422
        elif TestVersion(self.version) >= TestVersion("2.0"):
            code = 400
        else:
            code = 401
        utils.check_response_basic_info(resp, expected_method="POST", expected_code=code)

    @runner.MAGPIE_TEST_LOGIN
    def test_GetSignin_UsingParameters(self):
        """
        User is allowed to use its email as username for login.
        """
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

    def run_UpdateUsers_email_update_itself(self, user_path_variable):
        """
        Session user is allowed to update its own information via logged user path or corresponding user-name path.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_UpdateUser_ReservedKeyword_LoggedUser`
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
    def test_UpdateUsers_email_ReservedKeyword_LoggedUser(self):
        utils.warn_version(self, "user update its own information", "2.0.0", skip=True)
        self.run_UpdateUsers_email_update_itself(get_constant("MAGPIE_LOGGED_USER"))

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUsers_email_MatchingUserName_LoggedUser(self):
        utils.warn_version(self, "user update its own information", "2.0.0", skip=True)
        self.run_UpdateUsers_email_update_itself(self.test_user_name)

    def run_UpdateUsers_password_update_itself(self, user_path_variable):
        """
        Session user is allowed to update its own information via logged user path or corresponding user-name path.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_UpdateUser_ReservedKeyword_LoggedUser`
        """
        self.login_test_user()

        old_password = self.test_user_name
        new_password = "n0t-SO-ez-2-Cr4cK"  # nosec
        data = {"password": new_password}
        path = "/users/{usr}".format(usr=user_path_variable)
        resp = utils.test_request(self, self.update_method, path, json=data,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)
        utils.check_or_try_logout_user(self)

        # validate that the new password is effective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=new_password, use_ui_form_submit=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)
        utils.check_or_try_logout_user(self)

        # validate that previous password is ineffective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=old_password,
            use_ui_form_submit=True, expect_errors=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_UpdateUsers_password_ReservedKeyword_LoggedUser(self):
        utils.warn_version(self, "user update its own information", "2.0.0", skip=True)
        self.run_UpdateUsers_password_update_itself(get_constant("MAGPIE_LOGGED_USER"))

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUsers_password_MatchingUserName_LoggedUser(self):
        utils.warn_version(self, "user update its own information", "2.0.0", skip=True)
        self.run_UpdateUsers_password_update_itself(self.test_user_name)

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUsers_password_Forbidden_UpdateOthers(self):
        """
        Although session user is allowed to update its own information, insufficient permissions (not admin) forbids
        that user to update other user's information.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_UpdateUser_ReservedKeyword_LoggedUser`
        """
        utils.warn_version(self, "user update its own information", "2.0.0", skip=True)
        other_user_name = "unittest-user-auth_other-user-username"
        self.extra_user_names.add(other_user_name)
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user_name)
        utils.TestSetup.create_TestUser(self,
                                        override_user_name=other_user_name,
                                        override_password=other_user_name)
        self.login_test_user()

        new_password = "n0t-SO-ez-2-Cr4cK"  # nosec
        data = {"password": new_password}
        path = "/users/{usr}".format(usr=other_user_name)
        resp = utils.test_request(self, self.update_method, path, json=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)

        # validate that logged user password was not randomly updated
        # make sure we clear any potential leftover cookies by re-login
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=self.test_user_name, use_ui_form_submit=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)

        # validate that the new password was not applied to other user
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(
            self, username=other_user_name, password=other_user_name, use_ui_form_submit=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], other_user_name)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_UpdateUsers_username_Forbidden_ReservedKeyword_LoggedUser(self):
        """
        Logged user is not allowed to update its user name to reserved keyword.
        """
        self.login_test_user()
        logged = get_constant("MAGPIE_LOGGED_USER")
        data = {"user_name": logged}
        path = "/users/{}".format(logged)
        resp = utils.test_request(self, self.update_method, path, json=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)
        info = utils.TestSetup.get_UserInfo(self,
                                            override_headers=self.test_headers,
                                            override_cookies=self.test_cookies)
        utils.check_val_equal(info["user_name"], self.test_user_name)

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUsers_username_Forbidden_AnyNonAdmin(self):
        """
        Non-admin level user is not permitted to update its own user name.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_UpdateUser_username`
        """
        new_user_name = self.test_user_name + "new-user-name"
        self.extra_user_names.add(new_user_name)
        utils.TestSetup.delete_TestUser(self, override_user_name=new_user_name)
        self.login_test_user()

        data = {"user_name": new_user_name}
        path = "/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.test_request(self, self.update_method, path, json=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)
        info = utils.TestSetup.get_UserInfo(self,
                                            override_headers=self.test_headers,
                                            override_cookies=self.test_cookies)
        utils.check_val_equal(info["user_name"], self.test_user_name)

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUsers_username_Forbidden_UpdateOthers(self):
        """
        Logged user is not allowed to update any other user's name.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_UpdateUser_username`
        """
        other_user_name = "unittest-user-auth_other-user-username"
        self.extra_user_names.add(other_user_name)
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user_name)
        utils.TestSetup.create_TestUser(self,
                                        override_user_name=other_user_name,
                                        override_password=other_user_name)
        self.login_test_user()

        # actual test
        # does not even matter if other user exists or not, forbidden should be raised as soon as user mismatches
        new_test_user_name = other_user_name + "new-user-name"
        self.extra_user_names.add(new_test_user_name)
        data = {"user_name": new_test_user_name}
        path = "/users/{}".format(other_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)

        # valid other user not updated by test user, with admin access (if name not updated, it should be found)
        utils.check_or_try_logout_user(self)
        utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        resp = utils.test_request(self, "GET", path, cookies=self.cookies, headers=self.json_headers)
        utils.check_response_basic_info(resp)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_DeleteSelf(self):
        """
        Logged user is allowed to delete his own account.
        """
        utils.warn_version(self, "Delete the logged user's own account", "3.4.0", skip=True)

        # login as test user and delete its own account
        self.login_test_user()
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200, expected_method="GET")

        # verify if user cannot log back in
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  expect_errors=True,
                                  data={"user_name": self.test_user_name, "password": self.test_user_name})
        utils.check_response_basic_info(resp, 401, expected_method="POST")

        # login as admin and validate if test user doesn't exist
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  data={"user_name": self.usr, "password": self.pwd})
        utils.TestSetup.check_NonExistingTestUser(self)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_Forbidden_DeleteOthers(self):
        """
        Logged user is not allowed to delete other users.
        """
        # Create another user that the test user will try to delete
        other_user = self.test_user_name + "-other"
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user)
        utils.TestSetup.create_TestUser(self, override_user_name=other_user)

        # login as test user and try deleting the other account
        self.login_test_user()
        path = "/users/{usr}".format(usr=other_user)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        # validate the request is forbidden
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_Forbidden_ReservedKeyword_Admin(self):
        """
        Logged user is not allowed to delete special admin user.
        """
        # login as test user and try deleting the other account
        self.login_test_user()
        path = "/users/{usr}".format(usr=get_constant("MAGPIE_ADMIN_USER"))
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        # validate the request is forbidden
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_Forbidden_ReservedKeyword_Anonymous(self):
        """
        Logged user is not allowed to delete special anonymous user.
        """
        # login as test user and try deleting the other account
        self.login_test_user()
        path = "/users/{usr}".format(usr=get_constant("MAGPIE_ANONYMOUS_USER"))
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        # validate the request is forbidden
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    def test_PostUserGroup_Forbidden_SelfAssignMembership(self):
        """
        Non-admin level user cannot change its own group memberships nor any other user's group memberships.

        Non-admin user should only be able to change is own discoverable groups memberships through register routes,
        but not through this route which also accesses non-public groups for admin-only management.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_PostUserGroup_AllowAdmin_SelfAssignMembership`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_RegisterDiscoverableGroup`
        """
        test_group_name = "unittest-users-auth_new-group-self-assign"
        self.extra_group_names.add(test_group_name)
        utils.TestSetup.delete_TestGroup(self, override_group_name=test_group_name)  # in case of failing previous run
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
        """
        Logged user without administrator access is not allowed to add resource permissions for itself.
        """
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        body = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        self.login_test_user()

        res_id = body["resource_id"]
        perm = Permission.READ.value
        data = {"permission_name": perm}
        path = "/users/{}/resources/{}/permissions".format(get_constant("MAGPIE_LOGGED_USER"), res_id)
        resp = utils.test_request(self, "POST", path, data=data, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method="POST")
        path = "/users/{}/resources/{}/permissions".format(self.test_user_name, res_id)
        resp = utils.test_request(self, "GET", path, cookies=self.cookies, headers=self.json_headers)
        body = utils.check_response_basic_info(resp)
        utils.check_val_not_in(perm, body["permission_names"])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_SERVICES
    def test_GetUserServices_AllowedItself(self):
        """
        Validate that non-admin user can view services it has access to.

        Verifies access both when referenced to explicitly (by user-name) in path variable, and by logged user keyword.
        Without ``cascade`` query, user needs to have direct service permissions for it to be listed it in response.
        Otherwise nothing would be returned (i.e.: children resources are not searched for further permissions).

        .. seealso::
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserServices_ForbiddenOther`
            - :meth:`Interface_MagpieAPI_AdminAuth.test_GetUserServices_Cascade`
            - :meth:`Interface_MagpieAPI_AdminAuth.test_GetUserServices_CascadeAndInherited`
            - :meth:`Interface_MagpieAPI_AdminAuth.test_GetUserServices_Inherited`
        """
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.create_TestUserResourcePermission(self, resource_info=body)
        usr_svc_perm = info["permission_name"]
        self.login_test_user()
        expected_usr_svc_perms = utils.TestSetup.get_PermissionNames(self, usr_svc_perm)

        for user_path in [self.test_user_name, get_constant("MAGPIE_LOGGED_USER")]:
            path = "/users/{}/services".format(user_path)
            resp = utils.test_request(self, "GET", path, headers=self.test_headers, cookies=self.test_cookies)
            body = utils.check_response_basic_info(resp)
            utils.check_val_is_in("services", body)
            utils.check_val_is_in(self.test_service_type, body["services"])
            utils.check_val_equal(len(body["services"]), 1,
                                  msg="Only unique service with immediate user permission should be listed in types.")
            utils.check_val_is_in(self.test_service_name, body["services"][self.test_service_type])
            utils.check_val_equal(len(body["services"][self.test_service_type]), 1,
                                  msg="Only unique specific service with immediate user permission should be listed.")
            service = body["services"][self.test_service_type][self.test_service_name]  # type: JSON
            utils.check_all_equal(service["permission_names"], expected_usr_svc_perms, any_order=True,
                                  msg="Only single immediate permission applied on service for user should be listed.")
            utils.check_val_not_in("resources", service)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_SERVICES
    def test_GetUserServices_ForbiddenOther(self):
        """
        Validate that non-admin user cannot view another user's services.

        .. seealso::
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserServices_AllowedItself`
        """
        other_user = self.test_user_name + "-other"
        self.extra_user_names.add(other_user)
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user)
        utils.TestSetup.create_TestUser(self, override_user_name=other_user)
        self.login_test_user()

        path = "/users/{}/services".format(other_user)
        resp = utils.test_request(self, "GET", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_GetUserResources_AllowedItself(self):
        """
        Validate that non-admin user can view resources it has access to when referenced to explicitly in path variable
        instead of via logged user keyword.

        .. seealso::
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResources_ForbiddenOther`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResources_OnlyServicesWithPermissions`
        """
        body = utils.TestSetup.create_TestServiceResource(self)
        body = utils.TestSetup.create_TestUserResourcePermission(self, resource_info=body)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body, full_detail=True)
        child_perm, child_res_id = info["permission_names"][0], info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=child_res_id)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        leaf_perm, leaf_res_id = info["permission_names"][0], info["resource_id"]
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info)
        self.login_test_user()
        expect_child_perms = utils.TestSetup.get_PermissionNames(self, child_perm)
        expect_leaf_perms = utils.TestSetup.get_PermissionNames(self, leaf_perm)

        svc_types = utils.get_service_types_for_version(self.version)
        for user_path in [self.test_user_name, get_constant("MAGPIE_LOGGED_USER")]:
            path = "/users/{}/resources".format(user_path)
            resp = utils.test_request(self, "GET", path, headers=self.test_headers, cookies=self.test_cookies)
            body = utils.check_response_basic_info(resp)
            utils.check_val_is_in("resources", body)
            utils.check_val_equal(len(body["resources"]), len(svc_types))   # all service types always returned
            svc_of_type = body["resources"][self.test_service_type]         # service-level resources
            utils.check_val_is_in(self.test_service_name, svc_of_type)
            service = svc_of_type[self.test_service_name]  # type: JSON
            utils.check_val_equal(len(service["permission_names"]), 0)
            utils.check_val_is_in(str(child_res_id), service["resources"])  # first level resources
            child_res = service["resources"][str(child_res_id)]  # type: JSON
            utils.check_val_equal(len(child_res["permission_names"]), len(expect_child_perms))
            utils.check_all_equal(child_res["permission_names"], expect_child_perms, any_order=True,
                                  msg="Only single direct user permission applied on resource should be listed.")
            utils.check_val_is_in(str(leaf_res_id), child_res["children"])  # sub-level resources
            leaf_res = child_res["children"][str(leaf_res_id)]  # type: JSON
            utils.check_all_equal(leaf_res["permission_names"], expect_leaf_perms, any_order=True,
                                  msg="Only single direct user permission applied on resource should be listed.")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_GetUserResources_ForbiddenOther(self):
        """
        Validate that non-admin user cannot view another user's resources.

        .. seealso::
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResources_AllowedItself`
        """
        other_user = self.test_user_name + "-other"
        self.extra_user_names.add(other_user)
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user)
        utils.TestSetup.create_TestUser(self, override_user_name=other_user)
        self.login_test_user()

        path = "/users/{}/resources".format(other_user)
        resp = utils.test_request(self, "GET", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_GetUserResources_FilteredIgnoredForNonAdmin(self):
        """
        Validate that non-admin user cannot obtain non-filtered resources view.

        .. seealso::
            Use cases for admin-user views covered in:
              - :meth:`Interface_MagpieAPI_AdminAuth.Interface_MagpieAPI_AdminAuth`
              - :meth:`Interface_MagpieAPI_AdminAuth.test_GetUserResources_OnlyUserAndInheritedGroupPermissions`
            Returned values evaluated in:
              - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResources_OnlyServicesWithPermissions`
        """
        utils.warn_version(self, "filtered user resources view", "2.0.0", skip=True)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info)
        self.login_test_user()

        path = "/users/{}/resources?filtered=false".format(self.test_user_name)  # filtered=false should be ignored
        resp = utils.test_request(self, "GET", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp)
        svc_types = utils.get_service_types_for_version(self.version)
        utils.check_all_equal(svc_types, list(body["resources"]), any_order=True)
        for svc_type in svc_types:
            services = body["resources"][svc_type]
            # only validate expected service-resources are returned and not others
            # full permissions check done in other test cases
            if svc_type != self.test_service_type:
                utils.check_val_equal(services, {})
            else:
                utils.check_val_equal(list(services), [self.test_service_name])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_GetUserResources_OnlyServicesWithPermissions(self):
        """
        Validate that non-admin user execution the request gets filtered view of listed resources.

        .. versionadded:: 2.0
            Prior to this version, all services-specialized resources and every children resource would be recursively
            listed from this response, with empty permissions if none applied to user or inherited group permissions
            (accordingly to request queries).

            Starting with this version, service-resources that do no have any permission (either directly on service
            or at any level of any children resource, and still considering applicable user/group inheritance as per
            the request demands it), are completely removed from the response, if logged user executing the request
            does not have administrative level access.

            Verify that proper resources are returned in both only direct user and group inherited permissions cases.
        """
        utils.warn_version(self, "filter resource services with user/group permissions", "2.0.0", skip=True)
        svc_name_template = "{}_other-svc{{}}-resources-only-perms".format(self.test_service_name)

        # clean up edge case where previous execution failed, our test services could still exist
        # in this situation, they would be incorrectly detected as public services to be ignored!
        for i in range(3):
            utils.TestSetup.delete_TestService(self, override_service_name=svc_name_template.format(i))
        # get extra information
        path = "/groups/{}/resources".format(get_constant("MAGPIE_ANONYMOUS_GROUP"))
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        ignore_public_svc = set(body["resources"][self.test_service_type])

        # setup test data
        #   test-svc    [user perm]
        #   svc1        <none>
        #     res1      [user perm]
        #       res2    [group perm]
        #   svc2        <none>
        #     res3      [group perm]
        svc0_name = svc_name_template.format(0)
        utils.TestSetup.delete_TestService(self, override_service_name=svc0_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=svc0_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        body = utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info)
        svc0_perm = body["permission_name"]
        svc1_name = svc_name_template.format(1)
        utils.TestSetup.delete_TestService(self, override_service_name=svc1_name)
        body = utils.TestSetup.create_TestServiceResource(self, override_service_name=svc1_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res1_id = info["resource_id"]
        body = utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info)
        res1_perm = body["permission_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res1_id)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res2_id = info["resource_id"]
        body = utils.TestSetup.create_TestGroupResourcePermission(self, resource_info=info)
        res2_perm = body["permission_name"]
        svc2_name = svc_name_template.format(2)
        utils.TestSetup.delete_TestService(self, override_service_name=svc2_name)
        body = utils.TestSetup.create_TestServiceResource(self, override_service_name=svc2_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res3_id = info["resource_id"]
        body = utils.TestSetup.create_TestGroupResourcePermission(self, resource_info=info)
        res3_perm = body["permission_name"]
        self.login_test_user()

        expect_svc0_perms = utils.TestSetup.get_PermissionNames(self, svc0_perm)
        expect_res1_perms = utils.TestSetup.get_PermissionNames(self, res1_perm)
        expect_res2_perms = utils.TestSetup.get_PermissionNames(self, res2_perm)
        expect_res3_perms = utils.TestSetup.get_PermissionNames(self, res3_perm)

        # run test
        for query in ["", "?inherited=true"]:
            path = "/users/{}/resources{}".format(self.test_user_name, query)
            resp = utils.test_request(self, "GET", path, headers=self.test_headers, cookies=self.test_cookies)
            body = utils.check_response_basic_info(resp)
            utils.check_val_is_in("resources", body)
            svc_types = utils.get_service_types_for_version(self.version)
            utils.check_all_equal(list(body["resources"]), svc_types, any_order=True)
            for svc_type in svc_types:
                services = body["resources"][svc_type]  # type: JSON
                if svc_type == self.test_service_type:
                    expected_services = [svc0_name, svc1_name]
                    actual_services = set(services)
                    if query:
                        actual_services = actual_services - ignore_public_svc  # ignore inherited public group services
                        expected_services.append(svc2_name)  # but test-group-only resource permission make this listed
                    utils.check_all_equal(actual_services, expected_services, any_order=True)
                    svc0 = services[svc0_name]
                    utils.check_all_equal(svc0["permission_names"], expect_svc0_perms, any_order=True)
                    utils.check_val_equal(svc0["resources"], {})
                    svc1 = services[svc1_name]  # type: JSON
                    utils.check_all_equal(svc1["permission_names"], [])
                    utils.check_val_is_in(str(res1_id), svc1["resources"])
                    res1 = svc1["resources"][str(res1_id)]  # type: JSON
                    utils.check_all_equal(res1["permission_names"], expect_res1_perms, any_order=True)
                    if not query:
                        utils.check_val_not_in(str(res2_id), res1["children"])  # group-permission, not listed here
                    else:
                        utils.check_val_is_in(str(res2_id), res1["children"])  # but is listed when inherited here
                        res2 = res1["children"][str(res2_id)]  # type: JSON
                        utils.check_all_equal(res2["permission_names"], expect_res2_perms, any_order=True)
                        svc2 = services[svc2_name]  # type: JSON
                        utils.check_all_equal(svc2["permission_names"], [])  # no permission immediately on service
                        res3 = svc2["resources"][str(res3_id)]  # type: JSON
                        utils.check_all_equal(res3["permission_names"], expect_res3_perms, any_order=True)
                # note:
                #   if not testing the test-service-type, only evaluate expected empty resources when not inheriting
                #   from public group because that makes it much harder if some public permissions did already exist
                elif svc_type != self.test_service_type and not query:
                    msg = utils.json_msg(services, msg="Other service-resources without permissions must not be shown.")
                    utils.check_val_equal(len(body["resources"][svc_type]), 0, msg=msg)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_GetUserResourcesPermissions_AllowedItself(self):
        """
        Validate that non-admin user can view its own permissions when referenced to explicitly in path variable instead
        of via logged user keyword.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_GetLoggedUserResourcesPermissions`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResourcesPermissions_ForbiddenOther`
        """
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.create_TestUserResourcePermission(self, resource_info=body)
        res_id, res_perm = info["resource_id"], info["permission_name"]
        self.login_test_user()
        expected_perms = utils.TestSetup.get_PermissionNames(self, res_perm)

        for path_user in [self.test_user_name, get_constant("MAGPIE_LOGGED_USER")]:
            path = "/users/{}/resources/{}/permissions".format(path_user, res_id)
            resp = utils.test_request(self, "GET", path, headers=self.test_headers, cookies=self.test_cookies)
            body = utils.check_response_basic_info(resp)
            utils.check_val_is_in("permission_names", body)
            utils.check_all_equal(body["permission_names"], expected_perms, any_order=True,
                                  msg="Only single direct resource permission should be listed.")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_GetUserResourcesPermissions_ForbiddenOther(self):
        """
        Validate that non-admin user cannot view another user's permissions.

        .. seealso::
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResourcesPermissions_AllowedItself`
        """
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        other_user = self.test_user_name + "-other"
        self.extra_user_names.add(other_user)
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user)
        utils.TestSetup.create_TestUser(self, override_user_name=other_user)
        self.login_test_user()

        path = "/users/{}/resources/{}/permissions".format(other_user, info["resource_id"])
        resp = utils.test_request(self, "GET", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_REGISTER
    def test_RegisterDiscoverableGroup(self):
        """
        Non-admin logged user is allowed to update is membership to register to a discoverable group by itself.
        """
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
    @runner.MAGPIE_TEST_REGISTER
    def test_UnregisterDiscoverableGroup(self):
        """
        Non-admin logged user is allowed to revoke its membership to leave a discoverable group by itself.
        """
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
        """
        Non-admin logged user can view discoverable group information.

        Validate that critical details such as user names of members are not displayed.
        """
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
        """
        Non-admin logged user can view only available discoverable group names.
        """
        # setup some discoverable groups, but ignore others that *could* exist depending on the reference database
        # test user should have pre-assigned membership to non-discoverable test group (from setUp)
        # but that group must not be returned in the list of discoverable groups
        discover_before = set(utils.TestSetup.get_RegisteredGroupsList(self, only_discoverable=True))
        discover_groups = {self.test_group_name + "-1", self.test_group_name + "-2", self.test_group_name + "-3"}
        self.extra_group_names.update(discover_groups)
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
        """
        Non-admin logged user cannot delete a group although it is discoverable.
        """
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
@six.add_metaclass(ABCMeta)
class Interface_MagpieAPI_AdminAuth(AdminTestCase, BaseTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that require at least 'administrator' group
    AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

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
        utils.TestSetup.delete_TestService(cls)
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
    def test_GetLoggedUser(self):
        logged_user = get_constant("MAGPIE_LOGGED_USER")
        path = "/users/{}".format(logged_user)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.usr)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_GetLoggedUserResourcesPermissions(self):
        """
        Check visible permissions of logged user.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_GetLoggedUserResourcesPermissions_Queries`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResourcesPermissions_AllowedItself`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResourcesPermissions_ForbiddenOther`
        """
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        res_id = body["resource"]["resource_id"]
        self.check_GetUserResourcesPermissions(get_constant("MAGPIE_LOGGED_USER"), res_id)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_RESOURCES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_GetLoggedUserResourcesPermissions_Queries(self):
        """
        Validate returned logged user permissions with different query parameter modifiers.

        .. note::
            With later versions, effective permissions are evaluated by
            :meth:`test_GetUserResourcePermissions_EffectiveResolution` instead of within this test as rules require
            more advanced validations and conditions with the addition of :class:`Access` and :class:`Scope` concepts.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_GetLoggedUserResourcesPermissions`
            - :meth:`Interface_MagpieAPI_AdminAuth.test_GetUserResourcePermissions_EffectiveResolution`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResourcesPermissions_AllowedItself`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResourcesPermissions_ForbiddenOther`
        """
        utils.warn_version(self, "permission queries modifiers", "0.7.0", skip=True)

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
        perm_match = "read-match"  # backward compatibility
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

        expect_perm_match = utils.TestSetup.get_PermissionNames(self, perm_match)
        expect_perm_recur = utils.TestSetup.get_PermissionNames(self, perm_recur)

        # tests
        q_groups = "inherit=true"
        q_effect = "effective=true"
        test_effective = TestVersion(self.version) < TestVersion("3.0")
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=q_groups)
        utils.check_val_equal(body["permission_names"], [])
        if test_effective:
            body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_child_res_id, query=q_effect)
            utils.check_all_equal(body["permission_names"], expect_perm_recur, any_order=True)
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=q_groups)
        utils.check_all_equal(body["permission_names"], expect_perm_match, any_order=True)
        if test_effective:
            body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_parent_res_id, query=q_effect)
            utils.check_all_equal(body["permission_names"], expect_perm_recur + expect_perm_match, any_order=True)
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=None)
        utils.check_all_equal(body["permission_names"], expect_perm_recur, any_order=True)
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=q_groups)
        utils.check_all_equal(body["permission_names"], expect_perm_recur + expect_perm_match, any_order=True)
        if test_effective:
            body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_svc_res_id, query=q_effect)
            utils.check_all_equal(body["permission_names"], expect_perm_recur + expect_perm_match, any_order=True)

        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=None)
        utils.check_all_equal(body["permission_names"], expect_perm_match, any_order=True)
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=q_groups)
        utils.check_all_equal(body["permission_names"], expect_perm_match, any_order=True)
        if test_effective:
            body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_child_res_id, query=q_effect)
            utils.check_all_equal(body["permission_names"], expect_perm_recur + expect_perm_match, any_order=True)
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=q_groups)
        utils.check_val_equal(body["permission_names"], [])
        if test_effective:
            body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_parent_res_id, query=q_effect)
            utils.check_all_equal(body["permission_names"], expect_perm_recur, any_order=True)
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=None)
        utils.check_val_equal(body["permission_names"], [])
        body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=q_groups)
        utils.check_all_equal(body["permission_names"], expect_perm_recur, any_order=True)
        if test_effective:
            body = self.check_GetUserResourcesPermissions(anonym_usr, resource_id=test_svc_res_id, query=q_effect)
            utils.check_all_equal(body["permission_names"], expect_perm_recur, any_order=True)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_GetUserResourcesPermissions(self):
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        self.check_GetUserResourcesPermissions(self.usr, body["resource"]["resource_id"])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_PostUserResourcesPermissions_Created(self):
        resource_name = "post_res_perm_created"
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)
        body = utils.TestSetup.create_TestServiceResource(self, override_resource_name=resource_name)
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
    @runner.MAGPIE_TEST_RESOURCES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_PostUserResourcesPermissions_Conflict(self):
        resource_name = "post_res_perm_conflict"
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)
        body = utils.TestSetup.create_TestServiceResource(self, override_resource_name=resource_name)
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
    @runner.MAGPIE_TEST_RESOURCES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_UpdateUserResourcePermissions(self):
        utils.warn_version(self, "update user permissions", "3.0", skip=True)

        resource_name = "test-user-resource-update-no-conflict"
        utils.TestSetup.delete_TestServiceResource(self, override_resource_name=resource_name)
        body = utils.TestSetup.create_TestServiceResource(self, override_resource_name=resource_name)
        test_res_id = body["resource"]["resource_id"]

        path = "/users/{usr}/resources/{res}/permissions".format(res=test_res_id, usr=self.usr)
        data = {
            "permission": {
                "name": self.test_resource_perm_name,
                "access": Access.ALLOW.value,
                "scope": Scope.MATCH.value,
            }
        }
        # first request creates the permission when it doesn't exist, PUT works exactly as POST does without problem
        resp = utils.test_request(self, "PUT", path, data=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 201, expected_method="PUT")  # created, http code indicates new entity
        body = self.check_GetUserResourcesPermissions(self.usr, resource_id=test_res_id)
        perm = PermissionSet(data["permission"])
        utils.check_val_is_in("permission_names", body)
        utils.check_val_is_in(str(perm), body["permission_names"],
                              msg="Can't test for conflicting permissions if it doesn't exist first.")

        # second request updates the permission, without raising any conflict and handling delete of the older one
        data["permission"]["access"] = Access.DENY.value
        data["permission"]["scope"] = Scope.RECURSIVE.value
        resp = utils.test_request(self, "PUT", path, data=data, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="PUT")  # updated, http code is different
        perm = PermissionSet(data["permission"], typ=PermissionType.APPLIED)
        utils.check_val_is_in("permission_name", body)
        utils.check_val_is_in(str(perm), body["permission_name"], msg="Permission should have been modified.")
        utils.check_val_is_in("permission", body)
        utils.check_val_equal(perm.json(), body["permission"])

        # validate that fetch of updated permission only contains the new one (older one was deleted/replaced)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(len(body["permissions"]), 1)
        perm_body = body["permissions"][0]  # type: JSON
        utils.check_val_equal(perm_body["access"], data["permission"]["access"])
        utils.check_val_equal(perm_body["name"], data["permission"]["name"])
        utils.check_val_equal(perm_body["scope"], data["permission"]["scope"])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_DeleteUserResourcePermission(self):
        utils.warn_version(self, "delete user permissions with body", "3.0", skip=True)

        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestService(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]
        path = "/users/{usr}/resources/{res}/permissions".format(usr=self.test_user_name, res=res_id)
        data = {"permission_name": self.test_resource_perm_name}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, json=data)
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
    @runner.MAGPIE_TEST_SERVICES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_UpdateUserServicePermissions(self):
        utils.warn_version(self, "update user permissions", "3.0", skip=True)

        # setup initial permission on service
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=info["resource_id"])
        path = "/users/{}/services/{}/permissions".format(self.test_user_name, self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(len(body["permissions"]), 1)
        perm = body["permissions"][0]
        utils.check_val_equal(perm["access"], Access.ALLOW.value)
        utils.check_val_equal(perm["scope"], Scope.RECURSIVE.value)

        # update existing permission
        perm = {"name": perm["name"], "access": Access.DENY.value, "scope": Scope.MATCH.value}
        data = {"permission": perm}
        resp = utils.test_request(self, "PUT", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="PUT")
        perm.update({"type": PermissionType.DIRECT.value})
        expect_perms = [perm]

        # create new permission
        perm = {"name": Permission.WRITE.value}
        data = {"permission": perm}  # only name, others should use defaults
        resp = utils.test_request(self, "PUT", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 201, expected_method="PUT")
        perm.update({"access": Access.ALLOW.value, "scope": Scope.RECURSIVE.value, "type": PermissionType.DIRECT.value})
        expect_perms.append(perm)

        # validate both permissions exist
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        perms = body["permissions"]
        utils.check_val_equal(len(perms), 2, msg="New permission of different name should leave other intact.")
        utils.check_all_equal(perms, expect_perms, any_order=True)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_SERVICES
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_DeleteUserServicePermission(self):
        utils.warn_version(self, "delete user permissions with body", "3.0", skip=True)

        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestService(self)
        path = "/users/{usr}/services/{svc}/permissions".format(usr=self.test_user_name, svc=self.test_service_name)
        data = {"permission_name": self.test_service_perm}
        resp = utils.test_request(self, "POST", path, headers=self.json_headers, cookies=self.cookies, json=data)
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
    @runner.MAGPIE_TEST_RESOURCES
    @runner.MAGPIE_TEST_PERMISSIONS
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_GetUserResourcePermissions_EffectiveResolution(self):
        """
        Test effective resolution of permissions.

        Validates combinations of user/group inheritance combined with allow/deny and match/recursive modifiers.

        All resolved effective permissions are scoped as :attr:`Scope.MATCH` since they target a specific resource
        with pre-computed recursive resource tree inheritance. They should also have :attr:`PermissionType.EFFECTIVE`
        and the corresponding :class:`Scope` value whether the permission was set or not for the resolved groups/user.

        Legend::

            r: read
            w: write
            A: allow
            D: deny
            M: match
            R: recursive

        Permissions::
                                        user            group           effective (reason/importance)

            Service1                    (r-A-M)                         r-A, w-D  (default)
                Resource1               (w-A-M)         (r-A-R)         r-A, w-A
                    Resource2           (r-D-M)         (r-D-R)         r-D, w-D  (default + group-res2)
                        Resource3       (w-A-M)                         r-D, w-A  (group-res2)
            Service2                                                    r-D, w-D  (default)
                Resource4               (w-A-M)         (w-D-R)         r-D, w-A  (user > group)
                    Resource5           (r-A-R)         (r-D-M)         r-A, w-D  (user > group)
                        Resource6       (w-A-M)                         r-A. w-A  (user > group)
            Service3                    (w-D-M)         (w-A-R)         r-D, w-D  (user > group)
                Resource7                                               r-D, w-A  (group-svc3)
                    Resource8                           (w-D-R)         r-D, w-D  (revert group-svc3)
                        Resource9       (w-A-R)                         r-D, w-A  (user > group, revert group-res8)
        """
        utils.warn_version(self, "effective permissions resolution with deny", "3.0", skip=True)

        # create user/group and services/resources
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        svc1_name = "Service1-unittest-effective-permissions"
        svc2_name = "Service2-unittest-effective-permissions"
        svc3_name = "Service3-unittest-effective-permissions"
        for svc_name in [svc1_name, svc2_name, svc3_name]:
            utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=svc1_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body, full_detail=True)
        svc1_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=svc2_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body, full_detail=True)
        svc2_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=svc3_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body, full_detail=True)
        svc3_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc1_id, override_resource_name="Resource1")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res1_id, res1_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res1_id, override_resource_name="Resource2")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res2_id, res2_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res2_id, override_resource_name="Resource3")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res3_id, res3_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc2_id, override_resource_name="Resource4")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res4_id, res4_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res4_id, override_resource_name="Resource5")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res5_id, res5_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res5_id, override_resource_name="Resource6")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res6_id, res6_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc3_id, override_resource_name="Resource7")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res7_id, res7_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res7_id, override_resource_name="Resource8")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res8_id, res8_name = info["resource_id"], info["resource_name"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res8_id, override_resource_name="Resource9")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res9_id, res9_name = info["resource_id"], info["resource_name"]

        # apply permissions
        rAR = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)     # noqa
        rAM = PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH)         # noqa
        rDR = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)      # noqa
        rDM = PermissionSet(Permission.READ, Access.DENY, Scope.MATCH)          # noqa
        wAR = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)    # noqa
        wAM = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.MATCH)        # noqa
        wDR = PermissionSet(Permission.WRITE, Access.DENY, Scope.RECURSIVE)     # noqa
        wDM = PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)         # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc1_id, override_permission=rAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res1_id, override_permission=wAM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res1_id, override_permission=rAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res2_id, override_permission=rDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res2_id, override_permission=rDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res3_id, override_permission=wAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res4_id, override_permission=wAM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res4_id, override_permission=wDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res5_id, override_permission=rAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res5_id, override_permission=rDM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res6_id, override_permission=wAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc3_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc3_id, override_permission=wAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res8_id, override_permission=wDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res9_id, override_permission=wAR)

        def eval_perm_effective(res_name, res_id, perm, access):  # type: (str, int, Permission, Access) -> None
            path = "/users/{}/resources/{}/permissions?effective=true".format(self.test_user_name, res_id)
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200)  # noqa
            permissions = body["permissions"]
            utils.check_val_not_equal(len(permissions), 0)
            scope = Scope.MATCH.value
            msg = "Effective permission '{}' on resource '{}' expected '{}'.".format(perm.value, res_name, access.value)
            for obj in permissions:
                if Permission.get(obj["name"]) != perm:
                    continue
                utils.check_val_equal(Access.get(obj["access"]), access, msg=msg)
                utils.check_val_equal(obj["scope"], scope, msg="Resolved effective permission is always 'match'.")
                utils.check_val_equal(PermissionType.get(obj["type"]), PermissionType.EFFECTIVE, msg=msg)
                return  # validated
            raise AssertionError("{} Could not find it within response permissions: {}.".format(msg, permissions))

        # test
        eval_perm_effective(svc1_name, svc1_id, Permission.READ, Access.ALLOW)
        eval_perm_effective(svc1_name, svc1_id, Permission.WRITE, Access.DENY)
        eval_perm_effective(res1_name, res1_id, Permission.READ, Access.ALLOW)
        eval_perm_effective(res1_name, res1_id, Permission.WRITE, Access.ALLOW)
        eval_perm_effective(res2_name, res2_id, Permission.READ, Access.DENY)
        eval_perm_effective(res2_name, res2_id, Permission.WRITE, Access.DENY)
        eval_perm_effective(res3_name, res3_id, Permission.READ, Access.DENY)
        eval_perm_effective(res3_name, res3_id, Permission.WRITE, Access.ALLOW)
        eval_perm_effective(svc2_name, svc2_id, Permission.READ, Access.DENY)
        eval_perm_effective(svc2_name, svc2_id, Permission.WRITE, Access.DENY)
        eval_perm_effective(res4_name, res4_id, Permission.READ, Access.DENY)
        eval_perm_effective(res4_name, res4_id, Permission.WRITE, Access.ALLOW)
        eval_perm_effective(res5_name, res5_id, Permission.READ, Access.ALLOW)
        eval_perm_effective(res5_name, res5_id, Permission.WRITE, Access.DENY)
        eval_perm_effective(res6_name, res6_id, Permission.READ, Access.ALLOW)
        eval_perm_effective(res6_name, res6_id, Permission.WRITE, Access.ALLOW)
        eval_perm_effective(svc3_name, svc3_id, Permission.READ, Access.DENY)
        eval_perm_effective(svc3_name, svc3_id, Permission.WRITE, Access.DENY)
        eval_perm_effective(res7_name, res7_id, Permission.READ, Access.DENY)
        eval_perm_effective(res7_name, res7_id, Permission.WRITE, Access.ALLOW)
        eval_perm_effective(res8_name, res8_id, Permission.READ, Access.DENY)
        eval_perm_effective(res8_name, res8_id, Permission.WRITE, Access.DENY)
        eval_perm_effective(res9_name, res9_id, Permission.READ, Access.DENY)
        eval_perm_effective(res9_name, res9_id, Permission.WRITE, Access.ALLOW)

    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_GROUPS
    def test_GetLoggedUserGroups(self):
        path = "/users/{}/groups".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
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
        svc_type = ServiceNCWMS2.service_type
        res_type = Directory.resource_type_name
        utils.TestSetup.create_TestService(self, override_service_type=svc_type)
        body = utils.TestSetup.create_TestServiceResource(self, override_resource_type=res_type)
        res_id = body["resource"]["resource_id"]
        all_perms = deepcopy(SERVICE_TYPE_DICT[svc_type].permissions)
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
                self.test_user_name, self.test_group_name, self.test_service_name, svc_type, res_id)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserResources_OnlyUserAndInheritedGroupPermissions(self):
        """
        Test that compares expected responses from both only direct user permission and with group inherited
        permissions, as this, for every known service-type.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.setup_UniquePermissionsForEach_UserGroupServiceResource`
        """
        utils.warn_version(self, "inherited permissions", "0.7.4", skip=True)
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
            if TestVersion(self.version) >= TestVersion("1.4.0") and query:
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
        usr_svc_perms = utils.TestSetup.get_PermissionNames(self, perm_svc_usr)
        utils.check_all_equal(test_service["permission_names"], usr_svc_perms, any_order=True)
        utils.check_val_is_in(str(res_id), test_service["resources"])
        test_perms = test_service["resources"][str(res_id)]["permission_names"]  # noqa
        usr_res_perms = utils.TestSetup.get_PermissionNames(self, perm_res_usr)
        utils.check_all_equal(test_perms, usr_res_perms, any_order=True)

        # with inherit flag, both user and group permissions are visible on service and resource
        path = "/users/{usr}/resources?inherit=true".format(usr=usr_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        test_service = body["resources"][svc_type][svc_name]
        usr_grp_svc_perms = utils.TestSetup.get_PermissionNames(self, [perm_svc_usr, perm_svc_grp])
        utils.check_all_equal(test_service["permission_names"], usr_grp_svc_perms, any_order=True)
        utils.check_val_is_in(str(res_id), test_service["resources"])
        usr_res_perms = test_service["resources"][str(res_id)]["permission_names"]  # noqa
        expect_perms = utils.TestSetup.get_PermissionNames(self, [perm_res_usr, perm_res_grp])
        utils.check_all_equal(usr_res_perms, expect_perms, any_order=True)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserResources_Inherited_format(self):
        utils.warn_version(self, "inherited resource permissions", "0.7.4", skip=True)
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        svc_perm = SERVICE_TYPE_DICT[self.test_service_type].permissions[-1].value
        res_perms = SERVICE_TYPE_DICT[self.test_service_type].get_resource_permissions(self.test_resource_type)
        res_perm1 = res_perms[0].value
        res_perm2 = res_perms[-1].value
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc_id = info["resource_id"]
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission=svc_perm)
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc_id)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res1_id = info["resource_id"]
        utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info, override_permission=res_perm1)
        utils.TestSetup.create_TestGroupResourcePermission(self, resource_info=info, override_permission=res_perm2)
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res1_id)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res2_id = info["resource_id"]
        utils.TestSetup.create_TestGroupResourcePermission(self, resource_info=info, override_permission=res_perm2)
        if TestVersion(self.version) >= TestVersion("0.7.4"):
            path = "/users/{}/resources?inherit=true".format(self.test_user_name)
        else:
            # deprecated as of 0.7.4, removed in 2.0.0
            path = "/users/{}/inherited_resources".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("resources", body)
        utils.check_val_type(body["resources"], dict)
        service_types = utils.get_service_types_for_version(self.version)
        utils.check_all_equal(list(body["resources"]), service_types, any_order=True)
        for svc_type in body["resources"]:
            for svc in body["resources"][svc_type]:  # type: Str
                svc_dict = body["resources"][svc_type][svc]  # type: JSON
                # cannot blindly check permission values for all services since user could receive pre-existing
                # services inherited permissions from pre-defined anonymous group
                utils.TestSetup.check_ServiceFormat(self, svc_dict, has_private_url=False, skip_permissions=True)

        # validate permissions inherited on new test service/resources (ie: guaranteed no anonymous permissions)
        svc = body["resources"][self.test_service_type][self.test_service_name]  # type: JSON
        svc_perms = utils.TestSetup.get_PermissionNames(self, svc_perm)
        utils.check_all_equal(svc["permission_names"], svc_perms, any_order=True)  # direct user permission
        res1 = svc["resources"][str(res1_id)]  # type: JSON
        res1_perms = utils.TestSetup.get_PermissionNames(self, [res_perm1, res_perm2])  # user+group inherited
        utils.check_all_equal(res1["permission_names"], res1_perms, any_order=True)
        res2 = res1["children"][str(res2_id)]  # type: JSON
        res2_perms = utils.TestSetup.get_PermissionNames(self, res_perm2)  # only group inherited permission
        utils.check_all_equal(res2["permission_names"], res2_perms, any_order=True)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_RESOURCES
    def test_GetUserResources_Filtered(self):
        """
        Validate that admin-only operation is allowed for admin-user that requests filtered view.

        .. seealso::
            Use cases with non-filtered views covered in:
              - :meth:`Interface_MagpieAPI_AdminAuth.setup_UniquePermissionsForEach_UserGroupServiceResource`
              - :meth:`Interface_MagpieAPI_AdminAuth.test_GetUserResources_OnlyUserAndInheritedGroupPermissions`

            Use case for non-admin user:
              - :meth:`Interface_MagpieAPI_UsersAuth.test_GetUserResources_FilteredIgnoredForNonAdmin`
        :return:
        """
        utils.warn_version(self, "filtered user resource view for admin-only user", "2.0.0", skip=True)
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]
        perm = utils.TestSetup.create_TestUserResourcePermission(self, resource_info=info)
        res_perms = utils.TestSetup.get_PermissionNames(self, perm["permission_name"])
        # create another service without permission just to make sure it is not returned
        other_svc_name = "{}_service-filtered-user-resources".format(self.test_service_name)
        utils.TestSetup.delete_TestService(self, override_service_name=other_svc_name)
        utils.TestSetup.create_TestService(self, override_service_name=other_svc_name)

        path = "/users/{}/resources?filtered=true".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        svc_types = utils.get_service_types_for_version(self.version)
        utils.check_all_equal(list(body["resources"]), svc_types, any_order=True, msg="All service types listed.")
        for svc_type in svc_types:
            services = body["resources"][svc_type]  # type: JSON
            if svc_type != self.test_service_type:
                utils.check_val_equal(services, {})
            else:
                utils.check_val_equal(list(services), [self.test_service_name], msg="other service must not be listed")
                svc = services[self.test_service_name]  # type: JSON
                utils.check_val_equal(svc["permission_names"], [], msg="No permission directly on service.")
                utils.check_val_is_in(str(res_id), svc["resources"])
                res = svc["resources"][str(res_id)]  # type: JSON
                utils.check_all_equal(res["permission_names"], res_perms, any_order=True)

    def setup_GetUserServices(self):
        # type: () -> Dict[Str, Union[Str, List[Str], JSON]]
        """
        Setup element structure for tests:

            - :meth:`test_GetUserServices`
            - :meth:`test_GetUserServices_Flatten`
            - :meth:`test_GetUserServices_Cascade`
            - :meth:`test_GetUserServices_Inherit`
            - :meth:`test_GetUserServices_InheritAndCascade`

        Permission structure to evaluate different hierarchy interactions::

            svc1            [user:  perm1]
            svc2            [group: perm1]
            svc3            [user:  perm1, group: perm2]
            svc4            <none>
                res1        [user:  perm1]
                res2        [group: perm1]
                res3        [user:  perm1, group: perm2]
            svc5            <none>
                res4        <none>
                    res5    [user:  perm1]
                    res6    [group: perm1]
                    res7    [user:  perm1, group: perm2]

        All service and resources are respectively of same type.
        Using default test user/group.
        """
        svc_perms = [p.value for p in SERVICE_TYPE_DICT[self.test_service_type].permissions]
        res_type = list(SERVICE_TYPE_DICT[self.test_service_type].resource_types_permissions)[0]
        res_perms = [p.value for p in SERVICE_TYPE_DICT[self.test_service_type].resource_types_permissions[res_type]]
        test_items = {
            "svc_perms": svc_perms,
            "svc_perm1": svc_perms[0],
            "svc_perm2": svc_perms[-1],
            "res_perms": res_perms,
            "res_perm1": res_perms[0],
            "res_perm2": res_perms[-1],
            "svc_names": [],
        }

        # create service/resource structure
        for i in range(1, 6):
            svc_name = "{}_get-user-services_{}".format(self.test_service_name, i)
            self.extra_service_names.add(svc_name)
            test_items["svc_names"].append(svc_name)
            test_items["svc{}_name".format(i)] = svc_name
            utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
            svc_body = utils.TestSetup.create_TestService(self, override_service_name=svc_name)
            test_items["svc{}_info".format(i)] = utils.TestSetup.get_ResourceInfo(self, override_body=svc_body)
        svc4_id = test_items["svc4_info"]["resource_id"]
        for i in range(1, 4):
            res = "res{}".format(i)
            body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc4_id, override_resource_name=res)
            test_items["{}_info".format(res)] = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc5_id = test_items["svc5_info"]["resource_id"]
        res4 = "res4"
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc5_id, override_resource_name=res4)
        test_items["{}_info".format(res4)] = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res4_id = test_items["res4_info"]["resource_id"]
        for i in range(5, 8):
            res = "res{}".format(i)
            body = utils.TestSetup.create_TestResource(self, parent_resource_id=res4_id, override_resource_name=res)
            test_items["{}_info".format(res)] = utils.TestSetup.get_ResourceInfo(self, override_body=body)

        # create permissions directly on services
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        body = utils.TestSetup.create_TestUserResourcePermission(
            self, resource_info=test_items["svc1_info"], override_permission=test_items["svc_perm1"]
        )
        test_items["svc1_usr_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestGroupResourcePermission(
            self, resource_info=test_items["svc2_info"], override_permission=test_items["svc_perm1"]
        )
        test_items["svc2_grp_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestUserResourcePermission(
            self, resource_info=test_items["svc3_info"], override_permission=test_items["svc_perm1"]
        )
        test_items["svc3_usr_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestGroupResourcePermission(
            self, resource_info=test_items["svc3_info"], override_permission=test_items["svc_perm2"]
        )
        test_items["svc3_grp_perms"] = [body["permission_name"]]
        # create permissions on immediate children resources
        test_items["svc4_usr_perms"] = []
        test_items["svc4_grp_perms"] = []
        body = utils.TestSetup.create_TestUserResourcePermission(
            self, resource_info=test_items["res1_info"], override_permission=test_items["res_perm1"]
        )
        test_items["res1_usr_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestGroupResourcePermission(
            self, resource_info=test_items["res2_info"], override_permission=test_items["res_perm1"]
        )
        test_items["res2_grp_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestUserResourcePermission(
            self, resource_info=test_items["res3_info"], override_permission=test_items["res_perm1"]
        )
        test_items["res3_usr_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestGroupResourcePermission(
            self, resource_info=test_items["res3_info"], override_permission=test_items["res_perm2"]
        )
        test_items["res3_grp_perms"] = [body["permission_name"]]
        # create permission on sub-children resources
        test_items["svc5_usr_perms"] = []
        test_items["svc5_grp_perms"] = []
        test_items["res4_usr_perms"] = []
        test_items["res4_grp_perms"] = []
        body = utils.TestSetup.create_TestUserResourcePermission(
            self, resource_info=test_items["res5_info"], override_permission=test_items["res_perm1"]
        )
        test_items["res5_usr_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestGroupResourcePermission(
            self, resource_info=test_items["res6_info"], override_permission=test_items["res_perm1"]
        )
        test_items["res6_grp_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestUserResourcePermission(
            self, resource_info=test_items["res7_info"], override_permission=test_items["res_perm1"]
        )
        test_items["res7_usr_perms"] = [body["permission_name"]]
        body = utils.TestSetup.create_TestGroupResourcePermission(
            self, resource_info=test_items["res7_info"], override_permission=test_items["res_perm2"]
        )
        test_items["res7_grp_perms"] = [body["permission_name"]]
        return test_items

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServices(self):
        test_items = self.setup_GetUserServices()

        path = "/users/{}/services".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        services = body["services"]
        utils.check_val_type(services, dict)
        service_types = utils.get_service_types_for_version(self.version)
        # as of version 0.7.0, visible services depend on the connected user permissions,
        # so all services types not necessarily returned in the response
        if TestVersion(self.version) < TestVersion("0.7.0"):
            utils.check_all_equal(list(services), service_types, any_order=True)
        else:
            utils.check_all_equal(list(services), [self.test_service_type])
        # check format
        services = services[self.test_service_type]
        for svc_name in services:
            svc = services[svc_name]  # type: JSON
            utils.TestSetup.check_ServiceFormat(self, svc, has_children_resources=False, has_private_url=False,
                                                skip_permissions=True)  # check manually afterwards
        # check values - only services with direct user permissions should be listed
        expected_services = [test_items["svc1_name"], test_items["svc3_name"]]
        utils.check_all_equal(list(services), expected_services, any_order=True)
        svc1 = services[test_items["svc1_name"]]  # type: JSON
        svc3 = services[test_items["svc3_name"]]  # type: JSON
        svc1_perms = utils.TestSetup.get_PermissionNames(self, test_items["svc1_usr_perms"])
        svc3_perms = utils.TestSetup.get_PermissionNames(self, test_items["svc3_usr_perms"])
        utils.check_all_equal(svc1["permission_names"], svc1_perms, any_order=True)
        utils.check_all_equal(svc3["permission_names"], svc3_perms, any_order=True)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServices_Flatten(self):
        utils.warn_version(self, "flatten user services response format", "1.0.0", skip=True)
        flatten_query = "flatten" if TestVersion(self.version) >= TestVersion("2.0.0") else "list"
        test_items = self.setup_GetUserServices()

        path = "/users/{}/services?{}=true".format(self.test_user_name, flatten_query)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], list)
        utils.check_val_equal(len(body["services"]), 2, msg="services with direct user permissions expected")
        for svc in body["services"]:
            utils.TestSetup.check_ServiceFormat(self, svc, has_children_resources=False, has_private_url=False,
                                                skip_permissions=True)  # specific permissions validated in other tests
        expected_services = [test_items["svc1_name"], test_items["svc3_name"]]
        utils.check_all_equal([svc["service_name"] for svc in body["services"]], expected_services, any_order=True)

        # check it still works with other flags
        # note: cannot test number of services and expected service names because of inherited from anonymous
        #       other tests will validate these use-cases, only check format here
        path_var = path + "&inherited=true&cascade=true"
        resp = utils.test_request(self, "GET", path_var, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], list)
        for svc in body["services"]:
            utils.TestSetup.check_ServiceFormat(self, svc, has_children_resources=False, has_private_url=False,
                                                skip_permissions=True)  # specific permissions validated in other tests

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServices_Cascade(self):
        """
        Verify that all services which the user has :term:`Direct Permissions` on either the services themselves or one
        of their children resource at any level are returned.
        """
        utils.warn_version(self, "services with cascading permissions", "0.7.0", skip=True)
        test_items = self.setup_GetUserServices()

        path = "/users/{}/services?cascade=true".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], dict)
        utils.check_val_is_in(self.test_service_type, body["services"])
        utils.check_val_equal(len(body["services"]), 1,
                              msg="Only unique service-type using sub user-permissions should be listed.")
        services = body["services"][self.test_service_type]
        # since 'svc2' does not have any direct or children resource permission, it should not be returned
        utils.check_val_not_in(test_items["svc2_name"], services)
        expected_service_permissions = {
            # permission directly set on service, so services and their permissions should be listed
            test_items["svc1_name"]: test_items["svc1_usr_perms"],
            test_items["svc3_name"]: test_items["svc3_usr_perms"],
            # permission is on immediate children resource, so not listed, but service is shown
            test_items["svc4_name"]: test_items["svc4_usr_perms"],  # empty direct permissions
            # permission is on lower-level children resource, returned permissions are empty again but service listed
            test_items["svc5_name"]: test_items["svc5_usr_perms"],  # empty direct permissions
        }
        utils.check_all_equal(list(services), list(expected_service_permissions), any_order=True)
        for svc_name in services:
            svc = services[svc_name]  # type: JSON
            utils.TestSetup.check_ServiceFormat(self, svc, has_children_resources=False, has_private_url=False,
                                                override_permissions=expected_service_permissions[svc_name])

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServices_Inherited(self):
        """
        Validate user services returned with group inheritance.

        .. note::
            Since other permissions could be attributed to anonymous group and that it cannot be removed,
            we cannot explicitly check all services returned when group inheritance is applied.
            Only check newly created service permissions.

        .. warning::
            Group inheritance query parameter existed before ``2.0.0``, but was not producing the correct result
            for children resources permissions (all :term:`Allowed Permissions` were returned instead of
            user/group-specific :term:`Applied Permissions`).
        """
        utils.warn_version(self, "user service inheritance", "2.0.0", skip=True)
        resp = utils.test_request(self, "GET", "/services", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        prior_services = body["services"][self.test_service_type]
        test_items = self.setup_GetUserServices()

        path = "/users/{}/services?inherited=true".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], dict)
        utils.check_val_is_in(self.test_service_type, body["services"],
                              msg=utils.json_msg(body, "service type should be visible for service with permissions"))
        services = body["services"][self.test_service_type]
        # services that have children resource permissions are not listed (no cascade flag)
        utils.check_val_not_in(test_items["svc4_name"], services)
        utils.check_val_not_in(test_items["svc5_name"], services)
        expected_service_permissions = {
            # permission directly set on service, so services and their permissions should be listed
            test_items["svc1_name"]: test_items["svc1_usr_perms"],
            test_items["svc2_name"]: test_items["svc2_grp_perms"],
            test_items["svc3_name"]: test_items["svc3_usr_perms"] + test_items["svc3_grp_perms"],
        }
        for svc_name in services:
            svc = services[svc_name]  # type: JSON
            # still check format of non-test services, otherwise also check newly created expected permissions
            if svc_name in prior_services:
                skip_perm = True
                perms = utils.null
            else:
                skip_perm = False
                perms = expected_service_permissions[svc_name]
            utils.TestSetup.check_ServiceFormat(self, svc, has_children_resources=False, has_private_url=False,
                                                skip_permissions=skip_perm, override_permissions=perms)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServices_CascadeAndInherited(self):
        """
        Validate user services returned with group inheritance and cascading search of their children resources.

        .. note::
            Since other permissions could be attributed to anonymous group and that it cannot be removed,
            we cannot explicitly check all services returned when group inheritance is applied.
            Only check newly created service permissions.

        .. warning::
            Group inheritance query parameter existed before ``2.0.0``, but was not producing the correct result
            for children resources permissions (all :term:`Allowed Permissions` were returned instead of
            user/group-specific :term:`Applied Permissions`).
        """
        utils.warn_version(self, "user service inheritance", "2.0.0", skip=True)
        resp = utils.test_request(self, "GET", "/services", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        prior_services = body["services"][self.test_service_type]
        test_items = self.setup_GetUserServices()

        path = "/users/{}/services?inherited=true".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], dict)
        utils.check_val_is_in(self.test_service_type, body["services"],
                              msg=utils.json_msg(body, "service type should be visible for service with permissions"))
        services = body["services"][self.test_service_type]
        expected_service_permissions = {
            # permission directly set on service, so services and their permissions should be listed
            test_items["svc1_name"]: test_items["svc1_usr_perms"],
            test_items["svc2_name"]: test_items["svc2_grp_perms"],
            test_items["svc3_name"]: test_items["svc3_usr_perms"] + test_items["svc3_grp_perms"],
            # permission is on children resource immediately under service, so not listed, but service is shown
            test_items["svc4_name"]: test_items["svc4_usr_perms"],  # empty direct permissions
            # permission is on lower-level children resource, returned permissions are empty again but service listed
            test_items["svc5_name"]: test_items["svc5_usr_perms"],  # empty direct permissions
        }
        for svc_name in services:
            svc = services[svc_name]  # type: JSON
            # still check format of non-test services, otherwise also check newly created expected permissions
            if svc_name in prior_services:
                skip_perm = True
                perms = utils.null
            else:
                skip_perm = False
                perms = expected_service_permissions[svc_name]
            utils.TestSetup.check_ServiceFormat(self, svc, has_children_resources=False, has_private_url=False,
                                                skip_permissions=skip_perm, override_permissions=perms)
            # no sub resource should be indicated, only that user has permission "somewhere in the hierarchy"
            utils.check_val_not_in("resources", svc)
            utils.check_val_not_in("children", svc)

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServiceResources_format(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        path = "/users/{usr}/services/{svc}/resources".format(usr=self.usr, svc=self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("service", body)
        svc_dict = body["service"]
        utils.TestSetup.check_ServiceFormat(self, svc_dict, has_private_url=False, override_permissions=[])

    @runner.MAGPIE_TEST_USERS
    def test_GetUserServiceResources_OnlyUserAndInheritedGroupPermissions(self):
        values = self.setup_UniquePermissionsForEach_UserGroupServiceResource()
        perm_svc_usr, perm_svc_grp, perm_res_usr, perm_res_grp, usr_name, _, svc_name, svc_type, res_id = values

        # without inherit flag, only user permissions are visible on service and resource
        path = "/users/{usr}/services/{svc}/resources".format(usr=usr_name, svc=svc_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["service"]["service_name"], svc_name)
        utils.check_val_equal(body["service"]["service_type"], svc_type)
        usr_svc_perms = utils.TestSetup.get_PermissionNames(self, perm_svc_usr)
        utils.check_all_equal(body["service"]["permission_names"], usr_svc_perms, any_order=True)
        utils.check_val_is_in(str(res_id), body["service"]["resources"])
        usr_svc_res_perms = body["service"]["resources"][str(res_id)]["permission_names"]  # noqa
        expect_perms = utils.TestSetup.get_PermissionNames(self, perm_res_usr)
        utils.check_all_equal(usr_svc_res_perms, expect_perms, any_order=True)

        # with inherit flag, both user and group permissions are visible on service and resource
        path = "/users/{usr}/services/{svc}/resources?inherit=true".format(usr=usr_name, svc=svc_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["service"]["service_name"], svc_name)
        utils.check_val_equal(body["service"]["service_type"], svc_type)
        usr_grp_svc_perms = utils.TestSetup.get_PermissionNames(self, [perm_svc_usr, perm_svc_grp])
        utils.check_all_equal(body["service"]["permission_names"], usr_grp_svc_perms, any_order=True)
        utils.check_val_is_in(str(res_id), body["service"]["resources"])
        res_perms = body["service"]["resources"][str(res_id)]["permission_names"]  # noqa
        usr_grp_res_perms = utils.TestSetup.get_PermissionNames(self, [perm_res_usr, perm_res_grp])
        utils.check_all_equal(res_perms, usr_grp_res_perms, any_order=True)

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
        applicable_perms = info["permission_names"]
        applied_perm = applicable_perms[0]
        res_id = info["resource_id"]
        path = "/groups/{}/resources/{}/permissions".format(get_constant("MAGPIE_ANONYMOUS_GROUP"), res_id)
        data = {"permission_name": applied_perm}
        resp = utils.test_request(self, "POST", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        effective_perm_names = [applied_perm]
        if TestVersion(self.version) >= TestVersion("3.0"):
            effective_perm = PermissionSet(applied_perm, scope=Scope.MATCH)
            allowed_perm_names = utils.TestSetup.get_PermissionNames(self, effective_perm)
            denied_perm_names = {PermissionSet(perm).name for perm in applicable_perms} - {effective_perm.name}
            denied_perms = [PermissionSet(perm, access=Access.DENY, scope=Scope.MATCH) for perm in denied_perm_names]
            denied_perm_names = utils.TestSetup.get_PermissionNames(self, denied_perms)
            effective_perm_names = allowed_perm_names + denied_perm_names

        # test
        path = "/users/{}/resources/{}/permissions?effective=true".format(self.test_user_name, res_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("permission_names", body)
        utils.check_all_equal(effective_perm_names, body["permission_names"], any_order=True,
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
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        applicable_perms = info["permission_names"]
        applied_perm = applicable_perms[0]
        child_res_id = info["resource_id"]
        path = "/groups/{}/resources/{}/permissions".format(get_constant("MAGPIE_ANONYMOUS_GROUP"), parent_id)
        data = {"permission_name": applied_perm}
        resp = utils.test_request(self, "POST", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 201, expected_method="POST")

        # older API only returned existing permissions as allowed (missing ones being denied)
        # newer API always returns all applicable permissions during effective resolution, with Allow/Deny accordingly
        # furthermore, effective permissions are always 'MATCH' as they define access specifically for that item, with
        # all recursive parent resource inheritance pre-computed
        effective_perm = PermissionSet(applied_perm)
        if TestVersion(self.version) >= TestVersion("3.0"):
            effective_perm = PermissionSet(applied_perm, Access.ALLOW, Scope.MATCH, PermissionType.EFFECTIVE)

        # test
        path = "/users/{}/resources/{}/permissions?effective=true".format(self.test_user_name, child_res_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("permission_names", body)
        utils.check_val_is_in(effective_perm.implicit_permission, body["permission_names"],
                              msg="Permission applied to anonymous group which user is member of should be effective")
        if TestVersion(self.version) >= TestVersion("3.0"):
            perms_names = {PermissionSet(perm).name for perm in applicable_perms}
            perms_denied = [PermissionSet(perm, Access.DENY, Scope.MATCH, PermissionType.EFFECTIVE)
                            for perm in perms_names if perm != PermissionSet(applied_perm).name]
            effective_permissions = [effective_perm] + perms_denied
            utils.check_val_is_in("permissions", body)
            utils.check_all_equal([perm.json() for perm in effective_permissions], body["permissions"], any_order=True)

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
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.create_TestGroup(self)

        # must add valid data for other fields than tested one,
        # otherwise validation could fail because of missing details for other fields evaluated before targeted one
        data = {
            "user_name": self.test_user_name,
            "email": "{}@mail.com".format(self.test_user_name),
            "password": self.test_user_name,
            "group_name": self.test_group_name,
        }
        for i, (code, variant) in enumerate([
            (400, {"user_name": ""}),
            (400, {"user_name": "   "}),
            (400, {"user_name": "abc???def"}),
            (400, {"user_name": "abc/def"}),
            (400, {"user_name": "A" * 1024}),  # too long
            (400, {"email": ""}),
            (400, {"email": "   "}),
            (400, {"email": "abc???def"}),
            (400, {"email": "abc/def"}),
            (400, {"email": "abc-def @ gmail dot com"}),
            (400, {"password": ""}),
            (400, {"password": "abc"}),  # not long enough
            (400, {"group_name": "!ABC!"}),
            (400, {"group_name": "abc/def"}),
            (400, {"group_name": ""}),
        ]):
            var_data = deepcopy(data)
            var_data.update(variant)
            resp = utils.test_request(self, "POST", "/users", json=var_data, expect_errors=True,
                                      headers=self.json_headers, cookies=self.cookies)
            test_iter = "(Test #{})".format(i)  # 0-based index to help identify error cause during debugging
            info = utils.check_response_basic_info(resp, code, expected_method="POST", extra_message=test_iter)
            utils.check_val_equal(info["param"]["name"], list(variant.keys())[0],  # sanity check of failure reason
                                  msg="failing input validation was not accomplished for expected field")

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_NoGroupParam_DefaultsAnonymous(self):
        """
        Validate that user created with non-special keyword group also becomes a member of ``MAGPIE_ANONYMOUS_GROUP`` to
        ensure he will have access to publicly available resources.
        """
        utils.warn_version(self, "user creation without group parameter", "2.0.0", skip=True)
        utils.TestSetup.delete_TestUser(self)

        data = {
            "user_name": self.test_user_name,
            "email": "{}@mail.com".format(self.test_user_name),
            "password": self.test_user_name
        }
        utils.TestSetup.create_TestUser(self, override_data=data)
        utils.TestSetup.check_UserGroupMembership(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_PostUsers_ReservedKeyword_LoggedUser(self):
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
    def test_UpdateUser_ReservedKeyword_LoggedUser(self):
        """
        Logged user requested by special keyword path variable could not update its own password.

        .. versionchanged:: 2.0

            Logged user is correctly resolved to the corresponding context user.
            Provided that user has sufficient access rights, the operation is now permitted.
        """
        utils.warn_version(self, "logged user cannot update its own information", "2.0.0", older=True, skip=True)
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        path = "/users/{usr}".format(usr=get_constant("MAGPIE_LOGGED_USER"))
        new_user_name = self.test_user_name + "-new-put-over-logged-user"
        self.extra_user_names.add(new_user_name)
        data = {"user_name": new_user_name}
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method=self.update_method)

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUser_nothing(self):
        utils.TestSetup.create_TestUser(self, override_group_name=None)
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data={},
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method=self.update_method)

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUser_username(self):
        """
        Administrator level user is allowed to modify the username of another user.

        .. seealso::
            - :meth:`Interface_MagpieAPI_UsersAuth.test_UpdateUsers_username_Forbidden_AnyNonAdmin`
            - :meth:`Interface_MagpieAPI_UsersAuth.test_UpdateUsers_username_Forbidden_UpdateOthers`
        """
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        new_name = self.test_user_name + "-new"
        self.extra_user_names.add(new_name)
        # cleanup in case the updated username already exists (ex: previous test execution failure)
        utils.TestSetup.delete_TestUser(self, override_user_name=new_name)

        # update existing user name
        data = {"user_name": new_name}
        path = "/users/{}".format(self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)

        # validate change of user name
        path = "/users/{}".format(new_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], new_name)

        # validate removed previous user name
        path = "/users/{}".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method="GET")

        # validate effective new user name
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(self, username=new_name, password=self.test_user_name,
                                                         use_ui_form_submit=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], new_name)

        # validate ineffective previous user name
        utils.check_or_try_logout_user(self)
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=self.test_user_name,
            use_ui_form_submit=True, expect_errors=True)
        utils.check_val_equal(cookies, {}, msg="CookiesType should be empty from login failure.")
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_UpdateUser_username_ReservedKeyword_LoggedUser(self):
        """
        Even administrator level user is not allowed to update any user name to reserved keyword.
        """
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        data = {"user_name": get_constant("MAGPIE_LOGGED_USER")}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 403, expected_method=self.update_method)

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUser_email(self):
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
    def test_UpdateUser_password(self):
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        old_password = self.test_user_name
        new_password = "n0t-SO-ez-2-Cr4cK"  # nosec
        data = {"password": new_password}
        path = "/users/{}".format(self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)
        utils.check_or_try_logout_user(self)

        # validate that the new password is effective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=new_password, use_ui_form_submit=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["user_name"], self.test_user_name)
        utils.check_or_try_logout_user(self)

        # validate that previous password is ineffective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=old_password,
            use_ui_form_submit=True, expect_errors=True)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)

    @runner.MAGPIE_TEST_USERS
    def test_UpdateUser_PasswordTooShort(self):
        utils.warn_version(self, "user password min length validation", "2.0.0", skip=True)
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        data = {"password": pseudo_random_string(3)}
        path = "/users/{}".format(self.test_user_name)
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 400, expected_method=self.update_method)

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
                                             override_headers=self.json_headers, override_cookies=self.cookies)

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
        if TestVersion(self.version) >= TestVersion("1.4.0"):
            expected_groups.add(get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.check_all_equal(body["group_names"], expected_groups, any_order=True)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_DeleteSelf(self):
        """
        A generic admin user is allowed to delete his own account.
        """
        # Create a test admin user
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ADMIN_GROUP"))

        # login as test admin user and delete its own account
        utils.check_or_try_logout_user(self)
        self.test_headers, self.test_cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=self.test_user_name, use_ui_form_submit=True)

        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200, expected_method="GET")

        # verify if user cannot log back in
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  expect_errors=True,
                                  data={"user_name": self.test_user_name, "password": self.test_user_name})
        utils.check_response_basic_info(resp, 401, expected_method="POST")

        # login as admin and validate if the test admin user doesn't exist
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  data={"user_name": self.usr, "password": self.pwd})
        utils.TestSetup.check_NonExistingTestUser(self)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_DeleteOthers(self):
        """
        Admin user is allowed to delete other users.
        """
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.TestSetup.check_NonExistingTestUser(self)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_DeleteUser_SelfDelete_Forbidden_ReservedKeyword_Admin(self):
        """
        The special admin user cannot be self deleted.
        """
        admin = get_constant("MAGPIE_ADMIN_USER")
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(admin, users, msg="Admin user pre-requirement missing for test.")

        # Check if the special admin user cannot delete itself
        path = "/users/{}".format(admin)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(admin, users, msg="Admin special user should still exist.")

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_DeleteUser_DeleteOthers_Forbidden_ReservedKeyword_Admin(self):
        """
        The special admin user cannot be deleted by another admin.
        """
        admin = get_constant("MAGPIE_ADMIN_USER")
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(admin, users, msg="Admin user pre-requirement missing for test.")

        # Create a test admin user
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ADMIN_GROUP"))

        # login as test admin user
        utils.check_or_try_logout_user(self)
        self.test_headers, self.test_cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=self.test_user_name, use_ui_form_submit=True)

        # Attempt to delete the special admin
        path = "/users/{}".format(admin)
        resp = utils.test_request(self, "DELETE", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")

        # Delete the temporary admin user and sign back in to special admin user
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.test_headers, cookies=self.test_cookies)
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  data={"user_name": self.usr, "password": self.pwd})

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_DeleteUser_Forbidden_ReservedKeyword_Anonymous(self):
        """
        Even administrator level user is not allowed to remove the special anonymous user.
        """
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
        resp = utils.test_request(self, "DELETE", path, json={}, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
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
        utils.check_val_type(body["group"]["description"], utils.OPTIONAL_STRING_TYPES)
        utils.check_val_is_in("group_name", body["group"])
        utils.check_val_type(body["group"]["group_name"], six.string_types)
        utils.check_val_is_in("member_count", body["group"])
        utils.check_val_type(body["group"]["member_count"], int)
        if TestVersion(self.version) >= TestVersion("0.10.0"):
            utils.check_val_equal(body["group"]["member_count"], 1)
        else:
            utils.warn_version(self, "Member count invalid (always zero).", "0.10.0", skip=False)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroup_count(self):
        utils.warn_version(self, "Member count invalid (always zero).", "0.10.0", skip=True)

        utils.TestSetup.create_TestGroup(self)
        path = "/groups/{grp}".format(grp=self.test_group_name)
        for i in range(3):
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.check_val_equal(body["group"]["member_count"], i)
            user_name = "magpie-unittest-user-group-{}".format(i)
            self.extra_user_names.add(user_name)
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
        resp = utils.test_request(self, "POST", "/groups", json=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 409, expected_method="POST")

    @runner.MAGPIE_TEST_GROUPS
    def test_UpdateGroup_Name(self):
        new_group_name = "{}-new-name".format(self.test_group_name)
        self.extra_group_names.add(new_group_name)
        utils.TestSetup.delete_TestGroup(self, override_group_name=new_group_name)
        utils.TestSetup.create_TestGroup(self)

        path = "/groups/{}".format(self.test_group_name)
        data = {"group_name": new_group_name}
        resp = utils.test_request(self, self.update_method, path, json=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)
        resp = utils.test_request(self, "GET", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 404)

        path = "/groups/{}".format(new_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(body["group"]["group_name"], new_group_name)
        path = "/groups/{}".format(new_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200)

    @runner.MAGPIE_TEST_GROUPS
    def test_UpdateGroup_Discoverable(self):
        utils.TestSetup.create_TestGroup(self, override_discoverable=False)

        path = "/groups/{}".format(self.test_group_name)
        data = {"discoverable": True}
        resp = utils.test_request(self, self.update_method, path, json=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(body["group"]["discoverable"], True)

    @runner.MAGPIE_TEST_GROUPS
    def test_UpdateGroup_MultipleFields(self):
        data = {"group_name": self.test_group_name, "discoverable": True, "description": "test-group"}
        new_group_name = "{}-new-name".format(self.test_group_name)
        self.extra_group_names.add(new_group_name)
        utils.TestSetup.delete_TestGroup(self, override_group_name=new_group_name)
        utils.TestSetup.create_TestGroup(self, override_data=data)

        path = "/groups/{}".format(self.test_group_name)
        desc = "new-test-group"
        data = {"group_name": new_group_name, "discoverable": False, "description": desc}
        resp = utils.test_request(self, self.update_method, path, json=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)
        path = "/groups/{}".format(new_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(body["group"]["group_name"], new_group_name)
        utils.check_val_equal(body["group"]["discoverable"], False)
        utils.check_val_equal(body["group"]["description"], desc)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_DEFAULTS
    def test_DeleteGroup_forbidden_ReservedKeyword_Anonymous(self):
        """
        Even administrator level user is not allowed to remove the special keyword anonymous group.
        """
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
        """
        Even administrator level user is not allowed to remove the special keyword admin group.
        """
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
        resp = utils.test_request(self, "GET", path, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
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
        if TestVersion(self.version) < TestVersion("0.7.0"):
            utils.check_all_equal(list(services), service_types, any_order=True)
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
                if TestVersion(self.version) >= TestVersion("0.7.0"):
                    utils.check_val_is_in("service_sync_type", svc_dict)
                    utils.check_val_type(svc_dict["service_sync_type"], utils.OPTIONAL_STRING_TYPES)
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
        utils.TestSetup.check_ServiceFormat(self, svc_dict, has_private_url=False, override_permissions=[])

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_GetGroupServicePermissions(self):
        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=info["resource_id"])

        path = "/groups/{}/services/{}/permissions".format(self.test_group_name, self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        perm_names = utils.TestSetup.get_PermissionNames(self, self.test_service_perm)
        perm = PermissionSet(perm_names[-1], typ=PermissionType.APPLIED)
        utils.check_all_equal(body["permission_names"], perm_names, any_order=True)
        utils.check_val_equal(body["permissions"], [perm.json()])

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_UpdateGroupServicePermissions(self):
        utils.warn_version(self, "update group permissions", "3.0", skip=True)

        # setup initial permission on service
        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=info["resource_id"])

        path = "/groups/{}/services/{}/permissions".format(self.test_group_name, self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(len(body["permissions"]), 1)
        perm = body["permissions"][0]
        utils.check_val_equal(perm["access"], Access.ALLOW.value)
        utils.check_val_equal(perm["scope"], Scope.RECURSIVE.value)

        # update existing permission
        perm = {"name": perm["name"], "access": Access.DENY.value, "scope": Scope.MATCH.value}
        data = {"permission": perm}
        resp = utils.test_request(self, "PUT", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="PUT")
        perm.update({"type": PermissionType.APPLIED.value})
        expect_perms = [perm]

        # create new permission
        perm = {"name": Permission.WRITE.value}
        data = {"permission": perm}  # only name, others should use defaults
        resp = utils.test_request(self, "PUT", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 201, expected_method="PUT")
        perm.update({"access": Access.ALLOW.value,
                     "scope": Scope.RECURSIVE.value,
                     "type": PermissionType.APPLIED.value})
        expect_perms.append(perm)

        # validate both permissions exist
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        perms = body["permissions"]
        utils.check_val_equal(len(perms), 2, msg="New permission of different name should leave other intact.")
        utils.check_all_equal(perms, expect_perms, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_DeleteGroupServicePermissions(self):
        utils.warn_version(self, "delete group permissions with body", "3.0", skip=True)

        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res_id)

        # create 2 permissions to validate DELETE is only applied on targeted 'similar' permission by name
        other_perm = Permission.WRITE.value
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res_id,
                                                           override_permission=other_perm)

        path = "/groups/{}/services/{}/permissions".format(self.test_group_name, self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(len(body["permissions"]), 2)
        perm = body["permissions"][0]
        data = {"permission": perm}  # submit with JSON object
        resp = utils.test_request(self, "DELETE", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")

        # validate with GET because DELETE body does not have permission
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(len(body["permissions"]), 1)
        perm = body["permissions"][0]  # type: JSON
        utils.check_val_equal(perm["name"], other_perm)

        data = {"permission": other_perm}  # submit with name, should still find similar permission
        resp = utils.test_request(self, "DELETE", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")

        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(len(body["permission_names"]), 0)
        utils.check_val_equal(len(body["permissions"]), 0)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_DeleteGroupServicePermissionName(self):
        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        body = utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=info["resource_id"])
        perm = body["permission_name"]

        path = "/groups/{}/services/{}/permissions/{}".format(self.test_group_name, self.test_service_name, perm)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")

        # validate with GET because DELETE body does not have permission
        path = "/groups/{}/services/{}/permissions".format(self.test_group_name, self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(len(body["permission_names"]), 0)
        utils.check_val_equal(len(body["permissions"]), 0)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_GetGroupResourcePermissions(self):
        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res_id)

        path = "/groups/{}/resources/{}/permissions".format(self.test_group_name, res_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        perm_names = utils.TestSetup.get_PermissionNames(self, self.test_resource_perm_name)
        perm = PermissionSet(perm_names[-1], typ=PermissionType.APPLIED)
        utils.check_all_equal(body["permission_names"], perm_names, any_order=True)
        utils.check_val_equal(body["permissions"], [perm.json()])

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_UpdateGroupResourcePermissions(self):
        utils.warn_version(self, "update group permissions", "3.0", skip=True)

        # setup initial permission on service
        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=info["resource_id"])

        path = "/groups/{}/resources/{}/permissions".format(self.test_group_name, info["resource_id"])
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(len(body["permissions"]), 1)
        perm = body["permissions"][0]
        utils.check_val_equal(perm["access"], Access.ALLOW.value)
        utils.check_val_equal(perm["scope"], Scope.RECURSIVE.value)

        # update existing permission
        perm = {"name": perm["name"], "access": Access.DENY.value, "scope": Scope.MATCH.value}
        data = {"permission": perm}
        resp = utils.test_request(self, "PUT", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="PUT")
        perm.update({"type": PermissionType.APPLIED.value})
        expect_perms = [perm]

        # create new permission
        perm = {"name": Permission.WRITE.value}
        data = {"permission": perm}  # only name, others should use defaults
        resp = utils.test_request(self, "PUT", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 201, expected_method="PUT")
        perm.update({"access": Access.ALLOW.value,
                     "scope": Scope.RECURSIVE.value,
                     "type": PermissionType.APPLIED.value})
        expect_perms.append(perm)

        # validate both permissions exist
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        perms = body["permissions"]
        utils.check_val_equal(len(perms), 2, msg="New permission of different name should leave other intact.")
        utils.check_all_equal(perms, expect_perms, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_DeleteGroupResourcePermissions(self):
        utils.warn_version(self, "delete group permissions with body", "3.0", skip=True)

        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=info["resource_id"])

        path = "/groups/{}/resources/{}/permissions".format(self.test_group_name, info["resource_id"])
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(len(body["permissions"]), 1)
        perm = body["permissions"][0]
        data = {"permission": perm}
        resp = utils.test_request(self, "DELETE", path, json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")

        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_equal(len(body["permission_names"]), 0)
        utils.check_val_equal(len(body["permissions"]), 0)

    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_PERMISSIONS
    def test_DeleteGroupResourcePermissionName(self):
        utils.TestSetup.create_TestGroup(self)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        body = utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=info["resource_id"])
        perm = body["permission_name"]

        path = "/groups/{}/resources/{}/permissions/{}".format(self.test_group_name, info["resource_id"], perm)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")

        # validate with GET since no name returned in DELETE response
        path = "/groups/{}/resources/{}/permissions".format(self.test_group_name, info["resource_id"])
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(len(body["permission_names"]), 0)
        utils.check_val_equal(len(body["permissions"]), 0)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServices_ResponseFormat_Default(self):
        utils.TestSetup.create_TestService(self)
        resp = utils.test_request(self, "GET", "/services", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], dict)
        service_types = utils.get_service_types_for_version(self.version)
        utils.check_all_equal(list(body["services"]), service_types, any_order=True)
        for svc_type in body["services"]:
            for svc_name in body["services"][svc_type]:
                svc_info = body["services"][svc_type][svc_name]  # type: JSON
                utils.TestSetup.check_ServiceFormat(self, svc_info, has_children_resources=False)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServices_ResponseFormat_Flatten(self):
        utils.warn_version(self, "Service flattened listing as objects with query parameter", "2.0.0", skip=True)

        resp = utils.test_request(self, "GET", "/services", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        svc_name_list = []
        for svc_type in body["services"]:
            for svc_name in body["services"][svc_type]:
                svc_name_list.append(svc_name)

        path = "/services?flatten=true"
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("services", body)
        utils.check_val_type(body["services"], list)
        utils.check_val_equal(len(body["services"]), len(svc_name_list))
        for svc_info in body["services"]:  # type: JSON
            utils.TestSetup.check_ServiceFormat(self, svc_info, has_private_url=True, has_children_resources=False)
        service_names = [svc["service_name"] for svc in body["services"]]  # noqa
        utils.check_all_equal(service_names, svc_name_list, any_order=True)

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServices_ResponseFormat(self):
        body = utils.TestSetup.create_TestService(self)
        utils.check_val_is_in("service", body)
        utils.TestSetup.check_ServiceFormat(self, body["service"], has_private_url=True, has_children_resources=False)

    @runner.MAGPIE_TEST_SERVICES
    def test_PatchService_UpdateSuccess(self):
        body = utils.TestSetup.create_TestService(self)
        service = body["service"]
        new_svc_name = str(service["service_name"]) + "-updated"
        new_svc_url = str(service["service_url"]) + "/updated"
        self.extra_service_names.add(new_svc_name)
        utils.TestSetup.delete_TestService(self, override_service_name=new_svc_name)
        path = "/services/{svc}".format(svc=service["service_name"])
        data = {"service_name": new_svc_name, "service_url": new_svc_url}
        resp = utils.test_request(self, self.update_method, path, json=data,
                                  headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, expected_method=self.update_method)
        utils.check_val_is_in("service", body)
        utils.TestSetup.check_ServiceFormat(self, body["service"], has_private_url=True, has_children_resources=False)
        utils.check_val_equal(body["service"]["service_url"], new_svc_url)
        utils.check_val_equal(body["service"]["service_name"], new_svc_name)

    @runner.MAGPIE_TEST_SERVICES
    def test_PatchService_UpdateConflict(self):
        body = utils.TestSetup.create_TestService(self)
        service = body["service"]
        new_svc_name = str(service["service_name"]) + "-updated"
        new_svc_url = str(service["service_url"]) + "/updated"
        self.extra_service_names.add(new_svc_name)
        try:
            utils.TestSetup.create_TestService(self, override_service_name=new_svc_name)
            path = "/services/{svc}".format(svc=service["service_name"])
            data = {"service_name": new_svc_name, "service_url": new_svc_url}
            resp = utils.test_request(self, self.update_method, path, json=data, expect_errors=True,
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
        if TestVersion(self.version) >= TestVersion("0.9.5"):
            # directly interpreted as expected path `/services/types` behaviour, so method PATCH not allowed
            utils.check_response_basic_info(resp, 405, expected_method=self.update_method)
        else:
            # no path with service named 'types', filtered as not found
            utils.check_response_basic_info(resp, 404, expected_method=self.update_method)

    @runner.MAGPIE_TEST_SERVICES
    def test_PatchService_ReservedKeyword_Types(self):
        # try to PATCH on 'types' path should raise the error
        data = {"service_name": "dummy", "service_url": "dummy"}
        resp = utils.test_request(self, self.update_method, "/services/types", json=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)

        code = 404  # before update did not exist, path was not found
        if TestVersion(self.version) >= TestVersion("0.9.5"):
            code = 405  # directly interpreted as expected path `/services/types` behaviour, so method not allowed
        utils.check_response_basic_info(resp, expected_code=code, expected_method=self.update_method)

        utils.warn_version(self, "check for update service named 'types'", "0.9.1", skip=True)
        # try to PUT on valid service with new name 'types' should raise the error
        utils.TestSetup.create_TestService(self)
        path = "/services/{}".format(self.test_service_name)
        data = {"service_name": "types"}
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        code = 400  # before considered as bad request value
        if TestVersion(self.version) >= TestVersion("2.0.0"):
            code = 403  # later version distinguish with more explicit forbidden
        body = utils.check_response_basic_info(resp, code, expected_method=self.update_method)  # forbidden name 'types'
        utils.check_val_is_in("'types'", body["detail"])  # validate error message specific to this keyword

    @runner.MAGPIE_TEST_SERVICES
    def test_GetService_ResponseFormat(self):
        utils.TestSetup.create_TestService(self)
        path = "/services/{svc}".format(svc=self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        if TestVersion(self.version) < TestVersion("0.9.1"):
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
        if TestVersion(self.version) >= TestVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", svc_info)
            utils.check_val_type(svc_info["service_sync_type"], utils.OPTIONAL_STRING_TYPES)

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

        if TestVersion(self.version) >= TestVersion("3.1"):
            thredds_perms = [Permission.BROWSE.value, Permission.READ.value, Permission.WRITE.value]
        else:
            thredds_perms = [Permission.READ.value, Permission.WRITE.value]

        # evaluate different types of services
        for svc_type, svc_res_info in [
            # recursive child resource allowed
            (ServiceAPI.service_type,
                {"route": {
                    "perms": [Permission.READ.value, Permission.WRITE.value,
                              "read-match", "write-match"],  # backward compatibility
                    "child": True}}),
            # child resource allowed only for specific types
            (ServiceTHREDDS.service_type,
                {"directory": {
                    "perms": thredds_perms,
                    "child": True},
                 "file": {
                     "perms": thredds_perms,
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
                r_perms = utils.TestSetup.get_PermissionNames(self, r_type["perms"], combinations=True)
                utils.check_all_equal(r["permission_names"], r_perms, any_order=True)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServiceResources(self):
        utils.TestSetup.create_TestService(self)
        utils.TestSetup.create_TestServiceResource(self)
        path = "/services/{svc}/resources".format(svc=self.test_service_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in(self.test_service_name, body)
        svc_dict = body[self.test_service_name]
        utils.TestSetup.check_ServiceFormat(self, svc_dict)

    @runner.MAGPIE_TEST_SERVICES
    def test_GetServicePermissions(self):
        services_list = utils.TestSetup.get_RegisteredServicesList(self)

        for svc in services_list:
            svc_name = svc["service_name"]
            service_perms = [p.value for p in SERVICE_TYPE_DICT[svc["service_type"]].permissions]
            service_perms = utils.TestSetup.get_PermissionNames(self, service_perms, combinations=True)
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
        data = {
            "parent_id": service_id,
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        body = utils.TestSetup.create_TestServiceResource(self, override_data=data)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        utils.check_val_is_in("resource_id", info)
        utils.check_val_is_in("resource_name", info)
        utils.check_val_is_in("resource_type", info)
        utils.check_val_not_in(info["resource_id"], resources_prior_ids)
        utils.check_val_equal(info["resource_name"], self.test_resource_name)
        utils.check_val_equal(info["resource_type"], self.test_resource_type)

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServiceResources_ChildrenResource_ParentID(self):
        """
        Verify valid use case of children resource created under service's children resource with appropriate parent-ID.

        .. seealso::
            - :meth:`Interface_MagpieAPI_AdminAuth.test_PostServiceResources_ChildrenResource_ParentID_InvalidRoot`
        """
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
        if TestVersion(self.version) >= TestVersion("0.9.2"):
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
    def test_PostServiceResources_ChildrenResource_ParentID_InvalidRoot(self):
        """
        Ensure that providing ``parent_id`` corresponding to a resource *not* nested under the service represented by
        ``service_name`` in request path is validated preemptively to resource creation.

        .. seealso::
            :meth:`Interface_MagpieAPI_AdminAuth.test_PostServiceResources_ChildrenResource_ParentID`
        """
        utils.warn_version(self, "request service matches 'parent_id' resource's root-service", "2.0.0", skip=True)

        body = utils.TestSetup.create_TestService(self)
        utils.TestSetup.get_ResourceInfo(self, override_body=body)
        other_svc_name = "service-random-other"
        utils.TestSetup.delete_TestService(self, override_service_name=other_svc_name)
        body = utils.TestSetup.create_TestServiceResource(self, override_service_name=other_svc_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)

        path = "/services/{}/resources".format(self.test_service_name)
        data = {
            "resource_name": "resource-random-other",
            "resource_type": self.test_resource_type,
            "parent_id": info["resource_id"],  # resource not under 'test_service_name'
        }
        resp = utils.test_request(self, "POST", path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        code = 403 if TestVersion(self.version) >= TestVersion("3.0") else 400
        body = utils.check_response_basic_info(resp, code, expected_method="POST")
        utils.check_error_param_structure(body, version=self.version, param_compare_exists=True, param_name="parent_id")

    @runner.MAGPIE_TEST_SERVICES
    def test_PostServiceResources_DirectResource_Conflict(self):
        utils.TestSetup.create_TestServiceResource(self)
        path = "/services/{svc}/resources".format(svc=self.test_service_name)
        data = {"resource_name": self.test_resource_name, "resource_type": self.test_resource_type}
        resp = utils.test_request(self, "POST", path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
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
    def test_GetResources_ResponseFormat(self):
        utils.TestSetup.create_TestServiceResource(self)

        resp = utils.test_request(self, "GET", "/resources", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("resources", body)
        utils.check_val_type(body["resources"], dict)
        for service_type in body["resources"]:
            utils.check_val_type(body["resources"][service_type], dict)
            for resource_name in body["resources"][service_type]:
                resource = body["resources"][service_type][resource_name]  # type: JSON
                # top level resource is a service, should have corresponding details
                utils.check_val_is_in("resource_id", resource)
                utils.check_val_is_in("public_url", resource)
                utils.check_val_not_in("service_url", resource)  # explicitly omitted for this route
                utils.check_val_is_in("service_name", resource)
                utils.check_val_is_in("service_type", resource)
                utils.check_val_is_in("permission_names", resource)
                utils.check_val_type(resource["resource_id"], int)
                utils.check_val_type(resource["public_url"], six.string_types)
                utils.check_val_type(resource["service_name"], six.string_types)
                utils.check_val_type(resource["service_type"], six.string_types)
                utils.check_val_type(resource["permission_names"], list)
                if TestVersion(self.version) >= TestVersion("2.0.0"):
                    utils.check_val_not_equal(len(resource["permission_names"]), 0,
                                              msg="Resource route must always provide its applicable permissions.")
                    service_perms = [p.value for p in SERVICE_TYPE_DICT[resource["service_type"]].permissions]
                    service_perms = utils.TestSetup.get_PermissionNames(self, service_perms, combinations=True)
                    utils.check_all_equal(resource["permission_names"], service_perms, any_order=True)
                # children resources
                utils.check_val_is_in("resources", resource)
                children = resource["resources"]
                utils.check_val_type(children, dict)
                for res_id, child in children.items():
                    # test only one just to be sure of recursive nature (should have at least one from TestSetup)
                    # lower level resources are not services, therefore should not have those details
                    utils.check_val_not_in("public_url", child)
                    utils.check_val_not_in("service_url", child)
                    utils.check_val_not_in("service_name", child)
                    utils.check_val_not_in("service_type", child)
                    utils.check_val_is_in("resource_id", child)
                    utils.check_val_is_in("resource_name", child)
                    utils.check_val_is_in("resource_type", child)
                    utils.check_val_is_in("permission_names", child)
                    utils.check_val_type(child["resource_id"], int)
                    utils.check_val_type(child["resource_name"], six.string_types)
                    utils.check_val_type(child["resource_type"], six.string_types)
                    utils.check_val_type(child["permission_names"], list)
                    utils.check_val_equal(str(child["resource_id"]), res_id,
                                          msg="Key resource ID must match object's value, although of different types.")
                    if TestVersion(self.version) >= TestVersion("2.0.0"):
                        utils.check_val_not_equal(len(child["permission_names"]), 0,
                                                  msg="Resource route must always provide its applicable permissions.")
                    break  # stop after one

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
                                  headers=self.json_headers, cookies=self.cookies, json=data)
        body = utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.TestSetup.check_ResourceStructure(self, body, self.test_resource_name, self.test_resource_type)

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
        utils.TestSetup.check_ResourceStructure(self, body, self.test_resource_name, self.test_resource_type)

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
                                  headers=self.json_headers, cookies=self.cookies, json=data)
        body = utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.TestSetup.check_ResourceStructure(self, body, self.test_resource_name, self.test_resource_type)

    @runner.MAGPIE_TEST_RESOURCES
    def test_PostResources_MissingParentID(self):
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = utils.test_request(self, "POST", "/resources",
                                  headers=self.json_headers, cookies=self.cookies, data=data, expect_errors=True)
        # pre-check of existing parameter in request added for 400, then value gets validated for processing 422
        code = 422
        none = repr(None)
        if TestVersion(self.version) >= TestVersion("2.0.0"):
            if TestVersion(self.version) < TestVersion("3.0"):
                code = 400
            none = None
        body = utils.check_response_basic_info(resp, code, expected_method="POST")
        utils.check_error_param_structure(body, version=self.version, param_name="parent_id", param_value=none)

    @runner.MAGPIE_TEST_RESOURCES
    def test_PostResources_ConflictName(self):
        utils.warn_version(self, "check resource name unique under parent", "2.0.0", skip=True)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body, full_detail=True)
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": info["parent_id"],
        }
        resp = utils.test_request(self, "POST", "/resources", json=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 409, expected_method="POST")

    @runner.MAGPIE_TEST_RESOURCES
    def test_GetResource_ResponseFormat(self):
        """
        Test format of nested resource tree.

        Test structure::

            svc
              res1
                res3
              res2
        """
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body, full_detail=True)
        svc_id = info["parent_id"]
        res1_id = info["resource_id"]
        res_name = self.test_resource_name + "-other"
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc_id, override_resource_name=res_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res2_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res1_id)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res3_id = info["resource_id"]

        path = "/resources/{}".format(svc_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("resource", body)

        def check_resource_node(res_body, res_id, parent_id, root_id, perms, children_id):
            # type: (JSON, Optional[int], Optional[int], Optional[int], List[Permission], Optional[List[int]]) -> None
            utils.check_val_type(res_body, dict)
            utils.check_val_is_in("resource_name", res_body)
            utils.check_val_type(res_body["resource_name"], six.string_types)
            if TestVersion(self.version) >= TestVersion("0.7.0"):
                utils.check_val_is_in("resource_display_name", res_body)
                utils.check_val_type(res_body["resource_display_name"], six.string_types)
            utils.check_val_is_in("resource_id", res_body)
            utils.check_val_type(res_body["resource_id"], int)
            utils.check_val_equal(res_body["resource_id"], res_id)
            utils.check_val_is_in("parent_id", res_body)
            utils.check_val_equal(res_body["parent_id"], parent_id)
            if TestVersion(self.version) >= TestVersion("0.5.1"):
                utils.check_val_is_in("root_service_id", res_body)
                utils.check_val_equal(res_body["root_service_id"], root_id)
            utils.check_val_is_in("permission_names", res_body)
            utils.check_val_type(res_body["permission_names"], list)
            expect_perms = utils.TestSetup.get_PermissionNames(self, perms, combinations=True)
            utils.check_all_equal(res_body["permission_names"], expect_perms, any_order=True)
            utils.check_val_is_in("children", res_body)
            utils.check_val_type(res_body["children"], dict)
            if children_id is None:
                utils.check_val_equal(len(res_body["children"]), 0)
            else:
                utils.check_val_equal(len(res_body["children"]), len(children_id))
                for child_id in children_id:
                    utils.check_val_is_in(str(child_id), res_body["children"])

        # check details of every resource in tree
        svc_perms = SERVICE_TYPE_DICT[self.test_service_type].permissions
        res_perms = SERVICE_TYPE_DICT[self.test_service_type].get_resource_permissions(self.test_resource_type)
        check_resource_node(body["resource"], svc_id, None, None, svc_perms, [res1_id, res2_id])
        svc_body = body["resource"]  # type: JSON
        res1_body = svc_body["children"][str(res1_id)]  # type: JSON
        res2_body = svc_body["children"][str(res2_id)]  # type: JSON
        check_resource_node(res1_body, res1_id, svc_id, svc_id, res_perms, [res3_id])
        check_resource_node(res2_body, res2_id, svc_id, svc_id, res_perms, None)
        res3_body = res1_body["children"][str(res3_id)]
        check_resource_node(res3_body, res3_id, res1_id, svc_id, res_perms, None)

    @runner.MAGPIE_TEST_RESOURCES
    def test_UpdateResource(self):
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]
        res_new_name = self.test_resource_name + "_new-name-updated"

        data = {"resource_name": res_new_name}
        path = "/resources/{res_id}".format(res_id=res_id)
        resp = utils.test_request(self, self.update_method, path, data=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method=self.update_method)

        body = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        info = utils.check_response_basic_info(body)
        utils.check_val_equal(info["resource"]["resource_name"], res_new_name)

    @runner.MAGPIE_TEST_RESOURCES
    def test_UpdateResource_MissingName(self):
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]

        path = "/resources/{res_id}".format(res_id=res_id)
        resp = utils.test_request(self, self.update_method, path, data={}, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        code = 422 if TestVersion(self.version) >= TestVersion("3.0") else 400
        utils.check_response_basic_info(resp, code, expected_method=self.update_method)

    @runner.MAGPIE_TEST_RESOURCES
    def test_UpdateResource_SameName(self):
        utils.warn_version(self, "validate new resource name is different", "2.0.0", skip=True)
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]

        data = {"resource_name": self.test_resource_name}
        path = "/resources/{res_id}".format(res_id=res_id)
        resp = utils.test_request(self, self.update_method, path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 400, expected_method=self.update_method)

    @runner.MAGPIE_TEST_RESOURCES
    def test_DeleteResource(self):
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        resource_id = info["resource_id"]

        path = "/resources/{res_id}".format(res_id=resource_id)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")
        utils.TestSetup.check_NonExistingTestServiceResource(self)

    @runner.MAGPIE_TEST_RESOURCES
    def test_GetResourcePermissions_ResponseFormat(self):
        body = utils.TestSetup.create_TestServiceResource(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc_id)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]

        svc_perms = SERVICE_TYPE_DICT[self.test_service_type].permissions
        expect_svc_perms = utils.TestSetup.get_PermissionNames(self, svc_perms, combinations=True)
        path = "/resources/{}/permissions".format(svc_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("permission_names", body)
        utils.check_val_type(body["permission_names"], list)
        utils.check_all_equal(body["permission_names"], expect_svc_perms, any_order=True)

        res_perms = SERVICE_TYPE_DICT[self.test_service_type].get_resource_permissions(self.test_resource_type)
        expect_res_perms = utils.TestSetup.get_PermissionNames(self, res_perms, combinations=True)
        path = "/resources/{}/permissions".format(res_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("permission_names", body)
        utils.check_val_type(body["permission_names"], list)
        utils.check_all_equal(body["permission_names"], expect_res_perms, any_order=True)


@runner.MAGPIE_TEST_UI
@six.add_metaclass(ABCMeta)
class Interface_MagpieUI_NoAuth(NoAuthTestCase, BaseTestCase):
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
    def test_Swagger(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/api", expected_type=CONTENT_TYPE_HTML,
                                       expected_title=None)  # explicitly ignore title value check

    @runner.MAGPIE_TEST_STATUS
    def test_Login(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/login", expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewUsers(self):
        path = "/ui/users"
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups(self):
        path = "/ui/groups"
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServices(self):
        path = "/ui/services/default"
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

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
@six.add_metaclass(ABCMeta)
class Interface_MagpieUI_UsersAuth(UserTestCase, BaseTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie UI. Test any operation that require at least logged user AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.

    .. warning::
        After base setup completes, the remembered cookies are admin-level to allow setup of more specific test items
        per test case. It is necessary to call :meth:`login_test_user` after all setup data is completed in order to
        actually evaluate non-admin-level operations.

    .. seealso::
        - :meth:`UserTestCase.setUp`
        - :meth:`UserTestCase.login_test_user`
    """

    def __init__(self, *args, **kwargs):
        super(Interface_MagpieUI_UsersAuth, self).__init__(*args, **kwargs)
        self.magpie_title = "Magpie User Management"

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @classmethod
    def check_requirements(cls):
        utils.check_or_try_logout_user(cls)  # in case user changed during another test
        cls.require = "cannot run tests without logged admin user permissions to setup test data"
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd)
        assert cls.headers and cls.cookies, cls.require  # nosec

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
        """
        Logged user can view its own details on account page.
        """
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        path = "/ui/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.TestSetup.check_UpStatus(self, method="GET", path=path)
        utils.check_val_is_in("Account User", resp.text)
        utils.check_val_is_in(self.test_user_name, resp.text)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    def test_UserAccount_ViewDiscoverableGroupsMembership(self):
        """
        Logged user can view discoverable groups and which ones he has membership on.
        """
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        path = "/ui/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.TestSetup.check_UpStatus(self, method="GET", path=path)
        utils.check_val_is_in("Account User", resp.text)
        utils.check_val_is_in(self.test_user_name, resp.text)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_UserAccount_UpdateDetails_email(self):
        """
        Logged user can update its own email on account page.
        """
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        data = {"new_user_email": "new-mail@unittest-mail.com"}
        path = "/ui/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.TestSetup.check_FormSubmit(self, form_match="edit_email", form_submit="edit_email",
                                                method="GET", path=path)
        resp = utils.TestSetup.check_FormSubmit(self, form_match="edit_email", form_submit="save_email",
                                                form_data=data, previous_response=resp)
        utils.check_ui_response_basic_info(resp, expected_title="Magpie User Management")
        path = "/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp)
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["email"], data["new_user_email"])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_UserAccount_UpdateDetails_password(self):
        """
        Logged user can update its own password on account page.
        """
        utils.warn_version(self, "user account page", "2.0.0", skip=True)
        self.login_test_user()
        data = {"new_user_password": "12345678987654321"}
        # trigger the edit button form to obtain the 1st response with input field, then submit 2nd form with new value
        path = "/ui/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.TestSetup.check_FormSubmit(self, form_match="edit_password", form_submit="edit_password",
                                                method="GET", path=path)
        resp = utils.TestSetup.check_FormSubmit(self, form_match="edit_password", form_submit="save_password",
                                                form_data=data, previous_response=resp)
        utils.check_ui_response_basic_info(resp, expected_title="Magpie User Management")
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

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_LOGGED
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_UserAccount_DeleteSelf(self):
        """
        Logged user can delete his own account on account page.
        """
        utils.warn_version(self, "delete account on user account page", "3.4.0", skip=True)

        other_user = self.test_user_name + "-other"
        utils.TestSetup.delete_TestUser(self, override_user_name=other_user)
        utils.TestSetup.create_TestUser(self, override_user_name=other_user)
        utils.check_or_try_logout_user(self)

        self.headers, self.cookies = utils.check_or_try_login_user(self,
                                                                   username=other_user, password=self.test_user_name)

        # trigger the Delete Account button form to obtain the 1st response, then trigger the confirmation Delete button
        path = "/ui/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
        resp = utils.TestSetup.check_FormSubmit(self, form_match="delete_user", form_submit="delete",
                                                method="GET", path=path)
        utils.check_ui_response_basic_info(resp, expected_title="Magpie Administration")

        # verify if user cannot log back in
        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  expect_errors=True,
                                  data={"user_name": other_user, "password": self.test_user_name})
        utils.check_response_basic_info(resp, 401, expected_method="POST")

        resp = utils.test_request(self, "POST", "/signin", headers=self.json_headers, cookies={},
                                  data={"user_name": get_constant("MAGPIE_ADMIN_USER"),
                                        "password": get_constant("MAGPIE_ADMIN_PASSWORD")})
        utils.TestSetup.check_NonExistingTestUser(self, override_user_name=other_user)


@runner.MAGPIE_TEST_UI
@six.add_metaclass(ABCMeta)
class Interface_MagpieUI_AdminAuth(AdminTestCase, BaseTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie UI. Test any operation that require at least 'administrator' group
    AuthN/AuthZ.

    Derived classes must implement :meth:`setUpClass` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

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
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        form = {"edit": None, "user_name": self.test_user_name}
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path="/ui/users")
        if TestVersion(self.version) < "2":
            test = "Edit User: {}".format(self.test_user_name)
        else:
            test = "Edit User: [{}]".format(self.test_user_name)
        utils.check_val_is_in(test, resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/groups")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups_Goto_EditGroup(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.delete_TestUser(self)
        form = {"edit": None, "group_name": self.test_group_name}
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path="/ui/groups")
        if TestVersion(self.version) < "2":
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
        utils.TestSetup.create_TestService(self)
        form = {"edit": None, "service_name": self.test_service_name}
        path = "/ui/services/{}".format(self.test_service_type)
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path=path)
        find = "<span class=\"panel-value\">{}</span>".format(self.test_service_name)
        utils.check_val_is_in(find, resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUser(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        path = "/ui/users/{}/default".format(self.test_user_name)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUserService(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestService(self)
        path = "/ui/users/{usr}/{type}".format(usr=self.test_user_name, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroup(self):
        utils.TestSetup.create_TestGroup(self)
        path = "/ui/groups/{}/default".format(self.test_group_name)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroupService(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestService(self)
        path = "/ui/groups/{grp}/{type}".format(grp=self.test_group_name, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path, expected_type=CONTENT_TYPE_HTML)

    @runner.MAGPIE_TEST_STATUS
    def test_EditService(self):
        utils.TestSetup.create_TestService(self)
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


class SetupMagpieAdapter(object):
    """
    Configures all required :class:`MagpieAdapter` components to simulate how it would be loaded by `Twitcher` instance.

    Prepares references and provides :meth:`mock_request` method that can be employed to define a fake request similar
    to the ones that would be received by the proxy. This allows to test handling of the requests be the various
    components defined in the adapter.
    """
    session = None  # type: Optional[Session]

    @classmethod
    def setup_adapter(cls):
        test_app = utils.get_app_or_url(cls)
        settings = test_app.app.registry.settings
        adapter = MagpieAdapter(settings)
        config = adapter.configurator_factory(settings)
        # making the app triggers creation of class instances from registry (eg: AuthN/AuthZ Policies)
        config.make_wsgi_app()
        settings = config.registry.settings
        cls.ows = adapter.owssecurity_factory(settings)

    @classmethod
    def mock_request(cls, *args, **kwargs):
        """
        Set getters that are normally defined when running the full application.
        """
        request = utils.mock_request(*args, **kwargs)
        test_app = utils.get_app_or_url(cls)
        registry = test_app.app.registry
        request.registry = registry
        settings = kwargs.get("settings")
        if settings:
            request.registry.settings.update(settings)
        methods = registry.queryUtility(IRequestExtensions).descriptors
        # process the reify request methods as they would normally be generated by pyramid app
        # this ensures they become available as properties from the request (eg: request.db, request.user, etc.)
        # note: 'user' method depends on 'db', which itself depends on 'tm', ensure they are sorted
        methods = [(name, meth) for name, meth in methods.items() if name != "user"] + [("user", methods["user"])]
        for meth, reify in methods:
            # handle DB session manually, otherwise it gets duplicated and QueuePool limit gets reached
            if meth == "db":
                if not cls.session:
                    cls.session = reify.wrapped(request)
                setattr(request, meth, cls.session)
            else:
                setattr(request, meth, reify.wrapped(request))
        return request
