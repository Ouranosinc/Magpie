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
import tests.interfaces as ti
from magpie.constants import get_constant
from magpie.models import UserGroupStatus, UserStatuses
from magpie.utils import CONTENT_TYPE_JSON
from tests import runner, utils
from tests.utils import TestVersion


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
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.cookies = None  # force not logged in
        cls.version = utils.TestSetup.get_Version(cls)
        # note: admin credentials to setup data on test instance as needed, but not to be used for these tests
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.setup_admin()
        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-no-auth_api-user-local",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-no-auth_api-group-local",
                                           raise_missing=False, raise_not_set=False)


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
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        # admin login credentials for setup operations, use 'test' parameters for testing actual feature
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        assert cls.headers and cls.cookies, cls.require  # nosec

        cls.test_service_name = "unittest-user-auth-local_test-service"
        cls.test_service_type = "api"
        cls.test_resource_name = "unittest-user-auth-local_test-resource"
        cls.test_resource_type = "route"
        cls.test_group_name = "unittest-user-auth-local_test-group"
        cls.test_user_name = "unittest-user-auth-local_test-user-username"

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_GROUPS
    @runner.MAGPIE_TEST_REGISTRATION
    @utils.mocked_send_email
    def test_RegisterDiscoverableGroupWithTerms(self):
        """
        Non-admin logged user is allowed to request to join a group requiring terms and conditions acceptation.
        """
        terms = "Test terms and conditions."
        utils.TestSetup.delete_TestGroup(self)
        utils.TestSetup.create_TestGroup(self, override_discoverable=True, override_terms=terms)
        self.login_test_user()

        path = "/register/groups/{}".format(self.test_group_name)
        resp = utils.test_request(self, "POST", path, data={}, headers=self.test_headers, cookies=self.test_cookies)
        body = utils.check_response_basic_info(resp, 202, expected_method="POST")
        utils.check_val_is_in("group_name", body)
        utils.check_val_is_in("user_name", body)
        utils.check_val_is_in(body["group_name"], self.test_group_name)
        utils.check_val_is_in(body["user_name"], self.test_user_name)

        # validate as admin that user was not registered yet to the group,
        # since it requires terms and condition acceptation
        utils.check_or_try_logout_user(self)
        utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        utils.TestSetup.check_UserGroupMembership(self, member=False,
                                                  override_headers=self.json_headers, override_cookies=self.cookies)

        # Check if the user's membership is pending
        path = "/users/{user_name}/groups?status={status}".format(user_name=self.test_user_name,
                                                                  status=UserGroupStatus.PENDING.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")

        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)
        utils.check_val_is_in(self.test_group_name, body["group_names"])


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTRATION
class TestCase_MagpieAPI_UsersAuth_Local_UserRegistration(ti.UserTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require logged AuthN/AuthZ, but lower than ``MAGPIE_ADMIN_GROUP``.

    Use a local Magpie test application. Enables the User self-registration feature.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        # configuration employed for user registration tests
        settings = {
            "magpie.user_registration_enabled": True,
            "magpie.user_registered_enabled": True,
            "magpie.admin_approval_enabled": True,
            "magpie.admin_approval_email_recipient": "fake-admin@test.com",
        }
        cls.app = utils.get_test_magpie_app(settings)

        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        assert cls.headers and cls.cookies, cls.require  # nosec

        # don't bother with any test if not supported, must wait until here to get version from app
        utils.warn_version(cls, "User self-registration.", "3.13.0", skip=True)

        cls.test_group_name = "unittest-user-register-local_test-group"
        cls.test_user_name = "unittest-user-register-local_test-user-username"

    @runner.MAGPIE_TEST_USERS
    def test_GetPendingUsersList_Forbidden(self):
        """
        Non-admin logged user cannot list pending user registrations.
        """
        self.login_test_user()

        resp = utils.test_request(self, "GET", "/register/users", expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403)

    @runner.MAGPIE_TEST_USERS
    def test_DeletePendingUser_Forbidden(self):
        """
        Non-admin logged user cannot remove pending user registrations.
        """
        self.login_test_user()

        resp = utils.test_request(self, "DELETE", "/register/users/dont-care", expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 403, expected_method="DELETE")


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
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.login_admin()
        cls.setup_test_values()

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupUsers_Pending(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Create test user and request adding the user to test group, but leave him as 'pending'
        utils.TestSetup.create_TestUser(self, accept_terms=False)
        # Add admin user as an active member of test group
        utils.TestSetup.assign_TestUserGroup(self, override_user_name=self.usr)

        path = "/groups/{grp}/users?status={status}".format(grp=self.test_group_name,
                                                            status=UserGroupStatus.PENDING.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_all_equal(body["user_names"], {self.test_user_name}, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupUsers_Active(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Create test user and request adding the user to test group, but leave him as 'pending'
        utils.TestSetup.create_TestUser(self, accept_terms=False)
        # Add admin user as an active member of test group
        utils.TestSetup.assign_TestUserGroup(self, override_user_name=self.usr)

        path = "/groups/{grp}/users?status={status}".format(grp=self.test_group_name,
                                                            status=UserGroupStatus.ACTIVE.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_all_equal(body["user_names"], {self.usr}, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupUsers_Unspecified(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Create test user and request adding the user to test group, but leave him as 'pending'
        utils.TestSetup.create_TestUser(self, accept_terms=False)
        # Add admin user as an active member of test group
        utils.TestSetup.assign_TestUserGroup(self, override_user_name=self.usr)

        path = "/groups/{grp}/users".format(grp=self.test_group_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_all_equal(body["user_names"], {self.usr}, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetGroupUsers_All(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Create test user and request adding the user to test group, but leave him as 'pending'
        utils.TestSetup.create_TestUser(self, accept_terms=False)
        # Add admin user as an active member of test group
        utils.TestSetup.assign_TestUserGroup(self, override_user_name=self.usr)

        path = "/groups/{grp}/users?status={status}".format(grp=self.test_group_name,
                                                            status=UserGroupStatus.ALL.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_all_equal(body["user_names"], {self.usr, self.test_user_name}, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetUserInfo_PendingGroups(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Add user to users group
        users_group = get_constant("MAGPIE_USERS_GROUP")
        utils.TestSetup.create_TestUser(self, override_group_name=users_group)

        # Check if user info displays no current pending group
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user", body)
        utils.check_val_is_in("has_pending_group", body["user"])
        utils.check_val_false(body["user"]["has_pending_group"])

        # add user to test group and leave him as pending
        utils.TestSetup.assign_TestUserGroup(self, accept_terms=False)

        # Check if user info displays having a pending group
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("user", body)
        utils.check_val_is_in("has_pending_group", body["user"])
        utils.check_val_true(body["user"]["has_pending_group"])

    @runner.MAGPIE_TEST_GROUPS
    def test_GetUserGroups_Pending(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Add user to users group and leave user pending on test group
        users_group = get_constant("MAGPIE_USERS_GROUP")
        utils.TestSetup.create_TestUser(self, override_group_name=users_group)
        utils.TestSetup.assign_TestUserGroup(self, accept_terms=False)

        path = "/users/{usr}/groups?status={status}".format(usr=self.test_user_name,
                                                            status=UserGroupStatus.PENDING.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)
        utils.check_all_equal(body["group_names"], {self.test_group_name}, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetUserGroups_Active(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Add user to users group and leave user pending on test group
        users_group = get_constant("MAGPIE_USERS_GROUP")
        utils.TestSetup.create_TestUser(self, override_group_name=users_group)
        utils.TestSetup.assign_TestUserGroup(self, accept_terms=False)

        path = "/users/{usr}/groups?status={status}".format(usr=self.test_user_name,
                                                            status=UserGroupStatus.ACTIVE.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)

        expected_active_groups = {users_group}
        if TestVersion(self.version) >= TestVersion("1.4.0"):
            expected_active_groups.add(get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.check_all_equal(body["group_names"], expected_active_groups, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetUserGroups_Unspecified(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Add user to users group and leave user pending on test group
        users_group = get_constant("MAGPIE_USERS_GROUP")
        utils.TestSetup.create_TestUser(self, override_group_name=users_group)
        utils.TestSetup.assign_TestUserGroup(self, accept_terms=False)

        path = "/users/{usr}/groups".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)

        expected_active_groups = {users_group}
        if TestVersion(self.version) >= TestVersion("1.4.0"):
            expected_active_groups.add(get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.check_all_equal(body["group_names"], expected_active_groups, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    def test_GetUserGroups_All(self):
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)
        # Add user to users group and leave user pending on test group
        users_group = get_constant("MAGPIE_USERS_GROUP")
        utils.TestSetup.create_TestUser(self, override_group_name=users_group)
        utils.TestSetup.assign_TestUserGroup(self, accept_terms=False)

        path = "/users/{usr}/groups?status={status}".format(usr=self.test_user_name,
                                                            status=UserGroupStatus.ALL.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers,
                                  cookies=self.cookies, expect_errors=True)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)

        expected_groups = {users_group, self.test_group_name}
        if TestVersion(self.version) >= TestVersion("1.4.0"):
            expected_groups.add(get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.check_all_equal(body["group_names"], expected_groups, any_order=True)

    @runner.MAGPIE_TEST_GROUPS
    @utils.mocked_send_email
    def test_PostUserGroupWithTerms(self):
        # First test adding an existing user to a group with terms
        utils.TestSetup.create_TestUser(self, override_group_name=None)
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)

        # Request adding the user to test group
        path = "/users/{usr}/groups".format(usr=self.test_user_name)
        data = {"group_name": self.test_group_name}
        resp = utils.test_request(self, "POST", path, json=data,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 202, expected_method="POST")

        # User should not be added to group until terms are accepted
        utils.TestSetup.check_UserGroupMembership(self, member=False)

        # Now test adding a new user to a group with terms upon user creation
        new_user_name = "new_usr_in_group_with_terms"
        self.extra_user_names.add(new_user_name)
        data = {
            "user_name": new_user_name,
            "password": new_user_name,
            "group_name": self.test_group_name,
            "email": "{}@mail.com".format(new_user_name)
        }
        resp = utils.test_request(self, "POST", "/users", json=data, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 201, expected_method="POST")
        utils.TestSetup.check_UserGroupMembership(self, override_user_name=new_user_name, member=False)

        # Check if both user memberships are pending
        path = "/groups/{grp}/users?status={status}".format(grp=self.test_group_name,
                                                            status=UserGroupStatus.PENDING.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")

        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_val_is_in(self.test_user_name, body["user_names"])
        utils.check_val_is_in(new_user_name, body["user_names"])

    @runner.MAGPIE_TEST_GROUPS
    def test_PostUserGroupWithTerms_Fail(self):
        utils.TestSetup.create_TestUser(self, override_group_name=None)
        terms = "Test terms and conditions."
        utils.TestSetup.create_TestGroup(self, override_terms=terms)

        # Use empty settings dictionary, not assigning the MAGPIE_SMTP_HOST variable in the settings will
        # trigger a fail when assigning the user to the group with terms
        with utils.mocked_get_settings(settings={}):
            with utils.mock_send_email("magpie.api.management.user.user_utils.send_email"):
                path = "/users/{usr}/groups".format(usr=self.test_user_name)
                data = {"group_name": self.test_group_name}
                resp = utils.test_request(self, "POST", path, json=data, expect_errors=True,
                                                headers=self.json_headers, cookies=self.cookies)
                utils.check_response_basic_info(resp, 500, expected_method="POST")

        # Check that the user membership has not been updated as pending or as active
        path = "/groups/{grp}/users?status={status}".format(grp=self.test_group_name,
                                                            status=UserGroupStatus.ALL.value)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")

        utils.check_val_is_in("user_names", body)
        utils.check_val_type(body["user_names"], list)
        utils.check_val_not_in(self.test_user_name, body["user_names"])

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_NoExtraRegex_ValidRegex(self):
        """
        Check that the user_name_extra_regex setting is not used to validate a new user name when user_name_extra_regex
        is falsy.

        .. versionadded:: 3.37
        """
        utils.warn_version(self, "extra username regex added", "3.37", skip=True)
        with utils.mocked_get_settings(settings={"magpie.user_name_extra_regex": None}):
            data = {
                "user_name": self.test_user_name,
                "password": self.test_user_name,
                "email": "email@example.com",
            }
            resp = utils.test_request(self, "POST", "/users", data=data,
                                      headers=self.json_headers, cookies=self.cookies, expect_errors=True)
            utils.check_response_basic_info(resp, 201, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_WithExtraRegex_InvalidExtraRegex(self):
        """
        Check that the user_name_extra_regex setting is used to validate a new user name when the user name is
        invalid according to that regex but is valid according to the ax.PARAM_REGEX.

        .. versionadded:: 3.37
        """
        utils.warn_version(self, "extra username regex added", "3.37", skip=True)
        with utils.mocked_get_settings(settings={"magpie.user_name_extra_regex": "^$"}):
            data = {
                "user_name": self.test_user_name,
                "password": self.test_user_name,
                "email": "email@example.com",
            }
            resp = utils.test_request(self, "POST", "/users", data=data,
                                      headers=self.json_headers, cookies=self.cookies, expect_errors=True)
            utils.check_response_basic_info(resp, 400, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_WithExtraRegex_CaseInvalidExtraRegex(self):
        """
        Check that the user_name_extra_regex setting is used to validate a new user name when the user name is
        invalid according to that regex because the case is incorrect but is valid according to the ax.PARAM_REGEX.

        .. versionchanged:: 3.37.1
        """
        utils.warn_version(self, "case sensitive user name extra regex", "3.37.1", skip=True)
        with utils.mocked_get_settings(settings={"magpie.user_name_extra_regex": "^[a-z]+$"}):
            data = {
                "user_name": "UpperCaseUserName",
                "password": self.test_user_name,
                "email": "email@example.com",
            }
            resp = utils.test_request(self, "POST", "/users", data=data,
                                      headers=self.json_headers, cookies=self.cookies, expect_errors=True)
            utils.check_response_basic_info(resp, 400, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_WithExtraRegex_InvalidRegex(self):
        """
        Check that the user_name_extra_regex setting is used to validate a new user name when the user name is
        valid according to that regex but is invalid according to the ax.PARAM_REGEX.

        .. versionadded:: 3.37
        """
        utils.warn_version(self, "extra username regex added", "3.37", skip=True)
        with utils.mocked_get_settings(settings={"magpie.user_name_extra_regex": "^.*$"}):
            data = {
                "user_name": "email@example.com",
                "password": self.test_user_name,
                "email": "email@example.com",
            }
            resp = utils.test_request(self, "POST", "/users", data=data,
                                      headers=self.json_headers, cookies=self.cookies, expect_errors=True)
            utils.check_response_basic_info(resp, 400, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_WithExtraRegex_ValidBoth(self):
        """
        Check that the user_name_extra_regex setting is used to validate a new user name when the user name is
        valid according to that regex and the ax.PARAM_REGEX.

        .. versionadded:: 3.37
        """
        utils.warn_version(self, "extra username regex added", "3.37", skip=True)
        with utils.mocked_get_settings(settings={"magpie.user_name_extra_regex": "^.*$"}):
            data = {
                "user_name": self.test_user_name,
                "password": self.test_user_name,
                "email": "email@example.com",
            }
            resp = utils.test_request(self, "POST", "/users", data=data,
                                      headers=self.json_headers, cookies=self.cookies, expect_errors=True)
            utils.check_response_basic_info(resp, 201, expected_method="POST")


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTRATION
class TestCase_MagpieAPI_AdminAuth_Local_UserRegistration(ti.AdminTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.

    Use a local Magpie test application. Enables the User self-registration feature.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        # configuration employed for user registration tests
        settings = {
            "magpie.user_registration_enabled": True,
            "magpie.user_registered_enabled": True,
            "magpie.admin_approval_enabled": True,
            "magpie.admin_approval_email_recipient": "fake-admin@test.com",
        }

        # setup
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.app = utils.get_test_magpie_app(settings)
        cls.version = utils.TestSetup.get_Version(cls, real_version=True)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.login_admin()

        # don't bother with any test if not supported, must wait until here to get version from app
        utils.warn_version(cls, "User self-registration.", "3.13.0", skip=True)

    @runner.MAGPIE_TEST_USERS
    @utils.mocked_send_email
    def test_GetPendingUsersList(self):
        utils.TestSetup.clear_PendingUsers(self)

        test_user = "test-pending-user-listing"
        utils.TestSetup.create_TestUser(self, override_user_name=test_user, pending=True)

        resp = utils.test_request(self, "GET", "/register/users", headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200)
        utils.check_val_is_in("registrations", body)
        utils.check_val_equal(len(body["registrations"]), 1)
        utils.check_val_equal(body["registrations"][0], test_user)

    @runner.MAGPIE_TEST_USERS
    @utils.mocked_send_email
    def test_GetPendingUsersRegistration(self):
        utils.TestSetup.clear_PendingUsers(self)

        test_user = "test-pending-user-listing"
        utils.TestSetup.create_TestUser(self, override_user_name=test_user, pending=True)

        path = "/register/users/{}".format(test_user)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in("registration", body)
        reg = body["registration"]
        utils.check_val_is_in("user_name", reg)
        utils.check_val_equal(reg["user_name"], test_user)
        utils.check_val_is_in("status", reg)
        utils.check_val_equal(reg["status"], UserStatuses.Pending.name)
        utils.check_val_is_in("confirm_url", reg)
        utils.check_val_is_in("approve_url", reg)
        utils.check_val_is_in("decline_url", reg)

    @runner.MAGPIE_TEST_USERS
    @utils.mocked_send_email
    def test_DeletePendingUser(self):
        utils.TestSetup.clear_PendingUsers(self)

        test_user = "test-pending-user-listing"
        utils.TestSetup.create_TestUser(self, override_user_name=test_user, pending=True)

        path = "/register/users/{}".format(test_user)
        resp = utils.test_request(self, "DELETE", path, headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 200)

        resp = utils.test_request(self, "GET", path, expect_errors=True,
                                  headers=self.test_headers, cookies=self.test_cookies)
        utils.check_response_basic_info(resp, 404)


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
    def setUpClass(cls):
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls, real_version=True)
        # note: admin credentials to setup data on test instance as needed, but not to be used for these tests
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.setup_admin()
        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-no-auth_api-user-remote",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-no-auth_api-group-remote",
                                           raise_missing=False, raise_not_set=False)


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
    def setUpClass(cls):
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls, real_version=True)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged-in user with '{}' permissions".format(cls.grp)
        assert cls.headers and cls.cookies, cls.require  # nosec

        cls.test_service_name = "unittest-user-auth-remote_test-service"
        cls.test_service_type = "api"
        cls.test_resource_name = "unittest-user-auth-remote_test-resource"
        cls.test_resource_type = "route"
        cls.test_group_name = "unittest-user-auth-remote_test-group"
        cls.test_user_name = "unittest-user-auth-remote_test-user-username"


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
    def setUpClass(cls):
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.version = utils.TestSetup.get_Version(cls, real_version=True)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.login_admin()
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


@runner.MAGPIE_TEST_API
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_STATUS
def test_response_metadata():
    """
    Validate that regardless of response type (success/error) and status-code, metadata details are added.

    note: test only locally to avoid remote server side-effects and because mock cannot be done remotely
    """
    def raise_request(*_, **__):
        raise TypeError()

    app = utils.get_test_magpie_app()
    # all paths below must be publicly accessible
    for code, method, path, kwargs in [
        (200, "GET", "/session", {}),
        # FIXME: sort out 400 vs 422 everywhere (https://github.com/Ouranosinc/Magpie/issues/359)
        # (400, "POST", "/signin", {"body": {}}),  # missing credentials
        (401, "GET", "/services", {}),  # anonymous unauthorized
        (404, "GET", "/random", {}),
        (405, "POST", "/users/{}".format("MAGPIE_LOGGED_USER"), {"body": {}}),
        (406, "GET", "/session", {"headers": {"Accept": "application/pdf"}}),
        # 409: need connection to test conflict, no route available without so (other tests validates them though)
        (422, "POST", "/signin", {"body": {"user_name": "!!!!"}}),  # invalid format
        (500, "GET", "/json", {}),  # see mock
    ]:
        with mock.patch("magpie.api.schemas.generate_api_schema", side_effect=raise_request):
            headers = {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON}
            headers.update(kwargs.get("headers", {}))
            kwargs.pop("headers", None)
            resp = utils.test_request(app, method, path, expect_errors=True, headers=headers, **kwargs)
            # following util check validates all expected request metadata in response body
            utils.check_response_basic_info(resp, expected_code=code, expected_method=method)


if __name__ == "__main__":
    import sys
    sys.exit(unittest.main())  # type: ignore
