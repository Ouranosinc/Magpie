#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_ui
----------------------------------

Tests for :mod:`magpie.ui` module.
"""

import re
import unittest
from typing import TYPE_CHECKING

from six.moves.urllib.parse import urlparse

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti
from magpie.constants import get_constant
from magpie.models import Route, UserGroupType
from magpie.permissions import Access, Permission, PermissionSet, PermissionType, Scope
from magpie.services import ServiceAPI, ServiceWPS
from tests import runner, utils
from tests.utils import TestVersion

if TYPE_CHECKING:
    from typing import Union

    from magpie.typedefs import Str


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieUI_NoAuth_Local(ti.Interface_MagpieUI_NoAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that do not require any AuthN/AuthZ (``MAGPIE_ANONYMOUS_GROUP`` & ``MAGPIE_ANONYMOUS_USER``).

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.cookies = None
        # note: admin credentials to setup data on test instance as needed, but not to be used for these tests
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_missing=False, raise_not_set=False)
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_missing=False, raise_not_set=False)
        cls.setup_admin()
        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-no-auth_ui-user-local",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-no-auth_ui-group-local",
                                           raise_missing=False, raise_not_set=False)
        cls.test_service_type = ServiceWPS.service_type
        cls.test_service_name = "magpie-unittest-service-wps"


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieUI_UsersAuth_Local(ti.Interface_MagpieUI_UsersAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require logged user AuthN/AuthZ, but lower than ``MAGPIE_ADMIN_GROUP``.

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_missing=False, raise_not_set=False)
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_missing=False, raise_not_set=False)
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.version = utils.TestSetup.get_Version(cls)
        cls.setup_admin()
        cls.login_admin()
        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-user-auth_ui-user-local",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-user-auth_ui-group-local",
                                           raise_missing=False, raise_not_set=False)


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieUI_AdminAuth_Local(ti.Interface_MagpieUI_AdminAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_missing=False, raise_not_set=False)
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_missing=False, raise_not_set=False)
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.setup_admin()
        cls.login_admin()

        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-admin-auth_ui-user-local",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-admin-auth_ui-group-local",
                                           raise_missing=False, raise_not_set=False)
        cls.test_service_type = ServiceAPI.service_type
        cls.test_service_name = "magpie-unittest-ui-admin-local-service"
        cls.test_resource_type = Route.resource_type_name

        cls.test_service_parent_resource_type = ServiceAPI.service_type
        cls.test_service_parent_resource_name = "magpie-unittest-ui-tree-parent"
        cls.test_service_child_resource_type = Route.resource_type_name
        cls.test_service_child_resource_name = "magpie-unittest-ui-tree-child"

    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_EditService_Goto_AddChild_BackTo_EditService(self):
        """
        Verifies that UI button redirects are working for the following workflow:
            0. Starting on "Service View", press "Add Child" button (redirects to "New Resource" form)
            1. Fill form and press "Add" button (creates the service resource and redirects to "Service View")
            2. Back on "Service View", <new-resource> is visible in the list.

        Note:
            Only implemented locally with form submission of ``TestApp``.
        """
        try:
            # make sure any sub-resource are all deleted to avoid conflict, then recreate service to add sub-resource
            utils.TestSetup.delete_TestService(self, override_service_name=self.test_service_parent_resource_name)
            body = utils.TestSetup.create_TestService(self,
                                                      override_service_name=self.test_service_parent_resource_name,
                                                      override_service_type=self.test_service_parent_resource_type)
            svc_res_id = body["service"]["resource_id"]
            form = {"add_child": None, "resource_id": str(svc_res_id)}
            path = "/ui/services/{}/{}".format(self.test_service_parent_resource_type,
                                               self.test_service_parent_resource_name)
            resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="add_child", path=path)
            utils.check_val_is_in("New Resource", resp.text, msg=utils.null)    # add resource page reached
            data = {
                "resource_name": self.test_service_child_resource_name,
                "resource_type": self.test_service_child_resource_type,
            }
            resp = utils.TestSetup.check_FormSubmit(self, form_match="add_resource_form", form_submit="add_child",
                                                    form_data=data, previous_response=resp)
            for res_name in (self.test_service_parent_resource_name, self.test_service_child_resource_name):
                if TestVersion(self.version) >= TestVersion("3.0"):
                    find = "<div class=\"tree-key\">{}</div>".format(res_name)
                    text = resp.text.replace("\n", "").replace("  ", "")  # ignore formatting of source file
                else:
                    find = "<div class=\"tree-item\">{}</div>".format(res_name)
                    text = resp.text
                utils.check_val_is_in(find, text, msg=utils.null)
        finally:
            utils.TestSetup.delete_TestService(self, override_service_name=self.test_service_parent_resource_name)

    @runner.MAGPIE_TEST_STATUS
    @runner.MAGPIE_TEST_PERMISSIONS
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_EditUser_ApplyPermissions(self):
        """
        Verifies that UI button operations are working for the following workflow:
            0. Goto Edit User page.
            1. Change ``service-type`` tab to display services of type :class:`ServiceAPI`.
            2. Set new permissions onto an existing resources and submit them with ``Apply`` button.
            3. Verify the permissions are selected and displayed on page reload.
            4. Remove and modify permission from existing resource and submit.
            5. Validate that changes are reflected.

        Note:
            Only implemented locally with form submission of ``TestApp``.
        """
        utils.warn_version(self, "update permission modifiers with option select", "3.0", skip=True)

        # make sure any sub-resource are all deleted to avoid conflict, then recreate service to add sub-resource
        utils.TestSetup.delete_TestService(self)
        body = utils.TestSetup.create_TestService(self)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc_id, svc_name = info["resource_id"], info["service_name"]
        res_name = "resource1"
        sub_name = "resource2"
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc_id, override_resource_name=res_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res_id, override_resource_name=sub_name)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        sub_id = info["resource_id"]
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        # utilities for later tests
        def to_ui_permission(permission):
            # type: (Union[Str, PermissionSet]) -> Str
            return permission.explicit_permission if isinstance(permission, PermissionSet) else ""

        def check_ui_resource_permissions(perm_form, resource_id, permissions):
            select_res_id = "permission_resource_{}".format(resource_id)
            select_options = perm_form.fields[select_res_id]  # contains multiple select, one per applicable permission
            utils.check_val_equal(len(select_options), 2, msg="Always 2 select combobox expected (read and write).")
            select_values = [select.value for select in select_options]
            if not permissions:
                utils.check_all_equal(["", ""], select_values, msg="When no permission is selected, values are empty")
                return
            # value must match exactly the *explicit* permission representation
            for r_perm in permissions:
                utils.check_val_is_in(r_perm, select_values)

        def check_api_resource_permissions(resource_permissions):
            for _r_id, _r_perms in resource_permissions:
                urp_path = "/users/{}/resources/{}/permissions".format(self.test_user_name, _r_id)
                urp_resp = utils.test_request(self, "GET", urp_path)
                urp_body = utils.check_response_basic_info(urp_resp)
                ur_perms = [perm.json() for perm in _r_perms if isinstance(perm, PermissionSet)]
                for perm in ur_perms:
                    perm["type"] = PermissionType.DIRECT.value
                permissions = urp_body["permissions"]
                for perm in permissions:
                    perm.pop("reason", None)  # >= 3.4, don't care for this test
                utils.check_all_equal(permissions, ur_perms, any_order=True)

        # 0. goto user edit page (default first service selected)
        path = "/ui/users/{}/default".format(self.test_user_name)
        resp = utils.test_request(self, "GET", path)
        # 1. change to 'api' service-type, validate created test resources are all displayed in resource tree
        resp = resp.click(self.test_service_type)  # tabs are '<a href=...>{service-type}</a>'
        body = utils.check_ui_response_basic_info(resp)
        text = body.replace("\n", "").replace("  ", "")  # ignore HTML formatting
        tree_keys = re.findall(r"<div class=\"tree-key\">(.*?)</div>", text)
        for r_name in [svc_name, res_name, sub_name]:
            utils.check_val_is_in(r_name, tree_keys, msg="Resource '{}' expected to be listed in tree.".format(r_name))

        # 2. apply new permissions
        # 2.1 validate all initial values of permissions are empty
        res_form_name = "resources_permissions"  # form that wraps the displayed resource tree
        res_form_submit = "edit_permissions"     # id of the Apply 'submit' input of the form
        res_perm_form = resp.forms[res_form_name]
        for r_id in [svc_id, res_id, sub_id]:
            check_ui_resource_permissions(res_perm_form, r_id, [])
        # 2.2 apply new
        # NOTE: because tree-view is created by reversed order of permissions, we must provide them as [WRITE, READ]
        svc_perm1 = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)
        svc_perms = ["", svc_perm1]
        res_perm1 = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)
        res_perm2 = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)
        res_perms = [res_perm2, res_perm1]
        sub_perm1 = PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH)
        sub_perms = ["", sub_perm1]
        data = {
            # set value for following correspond to 'select' option that was chosen
            "permission_resource_{}".format(svc_id): [to_ui_permission(perm) for perm in svc_perms],
            "permission_resource_{}".format(res_id): [to_ui_permission(perm) for perm in res_perms],
            "permission_resource_{}".format(sub_id): [to_ui_permission(perm) for perm in sub_perms],
        }
        resp = utils.TestSetup.check_FormSubmit(self, previous_response=resp, form_match=res_perm_form,
                                                form_submit=res_form_submit, form_data=data)

        # 3. validate result
        # 3.1 validate displayed UI permissions
        res_perm_form = resp.forms[res_form_name]
        check_ui_resource_permissions(res_perm_form, svc_id, [to_ui_permission(perm) for perm in svc_perms])
        check_ui_resource_permissions(res_perm_form, res_id, [to_ui_permission(perm) for perm in res_perms])
        check_ui_resource_permissions(res_perm_form, sub_id, [to_ui_permission(perm) for perm in sub_perms])
        # 3.2 validate applied using API (to make sure that changes are not only reflected in UI)
        check_api_resource_permissions([(svc_id, svc_perms), (res_id, res_perms), (sub_id, sub_perms)])

        # 4. remove permission: this is equivalent to re-apply the ones we want to keep without the one to remove
        #    modify permission: this is detected by combo of (res-id, perm-name) with different (access, scope)
        svc_perms_mod = ["", ""]  # remove the previous (READ, ALLOW, RECURSIVE)
        res_perm1_mod = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)  # DENY -> ALLOW
        res_perms_mod = [res_perm2, res_perm1_mod]  # second WRITE permission is unchanged
        sub_perms_mod = sub_perms  # all unchanged for this resource
        data = {
            "permission_resource_{}".format(svc_id): [to_ui_permission(perm) for perm in svc_perms_mod],
            "permission_resource_{}".format(res_id): [to_ui_permission(perm) for perm in res_perms_mod],
            "permission_resource_{}".format(sub_id): [to_ui_permission(perm) for perm in sub_perms_mod],
        }
        resp = utils.TestSetup.check_FormSubmit(self, previous_response=resp, form_match=res_perm_form,
                                                form_submit=res_form_submit, form_data=data)

        # 5. validate applied permissions modifications
        res_perm_form = resp.forms[res_form_name]
        check_ui_resource_permissions(res_perm_form, svc_id, [to_ui_permission(perm) for perm in svc_perms_mod])
        check_ui_resource_permissions(res_perm_form, res_id, [to_ui_permission(perm) for perm in res_perms_mod])
        check_ui_resource_permissions(res_perm_form, sub_id, [to_ui_permission(perm) for perm in sub_perms_mod])
        check_api_resource_permissions([(svc_id, svc_perms_mod), (res_id, res_perms_mod), (sub_id, sub_perms_mod)])

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_FUNCTIONAL
    @runner.MAGPIE_TEST_GROUPS
    def test_end2end_user_join_group_with_terms_confirmation(self):
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        terms = "Test terms and conditions."
        group_with_terms_name = "unittest-admin-auth_ui-group-with-terms-local"
        utils.TestSetup.create_TestGroup(self, override_group_name=group_with_terms_name, override_discoverable=True,
                                         override_terms=terms)

        # custom app settings, smtp_host must exist when getting configs, but not used because email mocked
        settings = {"magpie.smtp_host": "example.com",
                    # for testing, ignore any 'from' and 'password' arguments that could be found in the .ini file
                    "magpie.smtp_from": "",
                    "magpie.smtp_password": ""}

        from magpie.api.notifications import make_email_contents as real_contents  # test contents with real generation
        with utils.mocked_get_settings(settings=settings):
            with utils.mock_send_email("magpie.api.management.user.user_utils.send_email") as email_contexts:
                _, wrapped_contents, mocked_send = email_contexts

                # Get current group's active members, for later checks
                path = "/users/{user_name}/groups".format(user_name=self.test_user_name)
                data = {"group_type": UserGroupType.ACTIVE_USERGROUPS.value}
                resp = utils.test_request(self, "GET", path, headers=self.json_headers, json=data, cookies=self.cookies)
                body = utils.check_response_basic_info(resp, 200, expected_method="GET")
                utils.check_val_is_in("group_names", body)
                active_members = body["group_names"]

                # Request adding the user to test group
                path = "/users/{usr}/groups".format(usr=self.test_user_name)
                data = {"group_name": group_with_terms_name}
                resp = utils.test_request(self, "POST", path, json=data,
                                          headers=self.json_headers, cookies=self.cookies)
                utils.check_response_basic_info(resp, 202, expected_method="POST")

                # Send a second request, to check later if both tmp_tokens are removed upon T&C acceptation
                resp = utils.test_request(self, "POST", path, json=data,
                                          headers=self.json_headers, cookies=self.cookies)
                utils.check_response_basic_info(resp, 202, expected_method="POST")

                # User should not be added to group until terms are accepted
                utils.TestSetup.check_UserGroupMembership(self, member=False,
                                                          override_group_name=group_with_terms_name)

                utils.check_val_equal(mocked_send.call_count, 2,
                                      msg="Expected sent notifications to user for an email confirmation "
                                          "of terms and conditions.")

                # Check if the user's membership is pending
                path = "/users/{user_name}/groups".format(user_name=self.test_user_name)
                data = {"group_type": UserGroupType.PENDING_USERGROUPS.value}
                resp = utils.test_request(self, "GET", path, headers=self.json_headers, json=data, cookies=self.cookies)
                body = utils.check_response_basic_info(resp, 200, expected_method="GET")

                utils.check_val_is_in("group_names", body)
                utils.check_val_type(body["group_names"], list)
                utils.check_val_is_in(group_with_terms_name, body["group_names"])
                pending_members = body["group_names"]

                # Check if getting all group's members finds both pending and active members
                path = "/users/{user_name}/groups".format(user_name=self.test_user_name)
                data = {"group_type": UserGroupType.ALL_USERGROUPS.value}
                resp = utils.test_request(self, "GET", path, headers=self.json_headers, json=data, cookies=self.cookies)
                body = utils.check_response_basic_info(resp, 200, expected_method="GET")
                utils.check_val_is_in("group_names", body)
                self.assertCountEqual(body["group_names"], pending_members + active_members)

                # validate that pending user can be viewed in the edit group page
                path = "/ui/groups/{}/default".format(group_with_terms_name)
                resp = utils.test_request(self, "GET", path)
                body = utils.check_ui_response_basic_info(resp)
                utils.check_val_is_in("{} [pending]".format(self.test_user_name), body)

                # validate that pending group membership can be viewed in the edit user page
                path = "/ui/users/{}/default".format(self.test_user_name)
                resp = utils.test_request(self, "GET", path)
                body = utils.check_ui_response_basic_info(resp)
                utils.check_val_is_in("{} [pending]".format(group_with_terms_name), body)

                # validate that pending group membership can be viewed in the user's account page
                utils.check_or_try_logout_user(self)
                utils.check_or_try_login_user(self, username=self.test_user_name, password=self.test_user_name,
                                              use_ui_form_submit=True)
                resp = utils.test_request(self, "GET", "/ui/users/current")
                body = utils.check_ui_response_basic_info(resp, expected_title="Magpie")
                utils.check_val_is_in("{} [pending]".format(group_with_terms_name), body)

                # Validate the content of the email that would have been sent if not mocked
                message = real_contents(*wrapped_contents.call_args.args, **wrapped_contents.call_args.kwargs)
                msg_str = message.decode()

                confirm_url = wrapped_contents.call_args.args[-1].get("confirm_url")

                test_user_email = "{}@mail.com".format(self.test_user_name)
                utils.check_val_is_in("To: {}".format(test_user_email), msg_str)
                utils.check_val_is_in("From: Magpie", msg_str)
                utils.check_val_is_in(confirm_url, msg_str)
                utils.check_val_true(confirm_url.startswith("http://localhost") and "/tmp/" in confirm_url,
                                     msg="Expected confirmation URL in email to be a temporary token URL.")

                # Simulate user clicking the confirmation link in 'sent' email (external operation from Magpie)
                resp = utils.test_request(self, "GET", urlparse(confirm_url).path)
                body = utils.check_ui_response_basic_info(resp, 200)
                utils.check_val_is_in("accepted the terms and conditions", body)

                utils.check_val_equal(mocked_send.call_count, 3,
                                      msg="Expected sent notification to user for an email confirmation of user added "
                                          "to requested group, following terms and conditions acceptation.")

                # Log back to admin user to apply admin-only checks
                utils.check_or_try_logout_user(self)
                self.login_admin()

                # Check if user has been added to group successfully
                utils.TestSetup.check_UserGroupMembership(self, override_group_name=group_with_terms_name)
                path = "/groups/{grp}".format(grp=group_with_terms_name)
                resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
                body = utils.check_response_basic_info(resp, 200, expected_method="GET")
                utils.check_val_equal(body["group"]["member_count"], 1)
                utils.check_val_is_in(self.test_user_name, body["group"]["user_names"])

                # UI checks: validates that both test tmp_tokens were deleted if '[pending]' is not displayed anymore
                # validate that user is no longer pending in the edit group page
                path = "/ui/groups/{}/default".format(group_with_terms_name)
                resp = utils.test_request(self, "GET", path)
                body = utils.check_ui_response_basic_info(resp)
                utils.check_val_not_in("{} [pending]".format(self.test_user_name), body)

                # validate that group membership is no longer pending in the edit user page
                path = "/ui/users/{}/default".format(self.test_user_name)
                resp = utils.test_request(self, "GET", path)
                body = utils.check_ui_response_basic_info(resp)
                utils.check_val_not_in("{} [pending]".format(group_with_terms_name), body)

                # validate that group membership is no longer pending in the user's account page
                utils.check_or_try_logout_user(self)
                utils.check_or_try_login_user(self, username=self.test_user_name, password=self.test_user_name,
                                              use_ui_form_submit=True)
                resp = utils.test_request(self, "GET", "/ui/users/current")
                body = utils.check_ui_response_basic_info(resp, expected_title="Magpie")
                utils.check_val_not_in("{} [pending]".format(group_with_terms_name), body)

            assert 0


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTRATION
class TestCase_MagpieUI_UserRegistration_Local(ti.UserTestCase, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.

    Use a local Magpie test application. Enables the User self-registration feature.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        # minimally, must setup the test app to provide the required routes
        # other settings related to user registration are set specifically for each test variation
        settings = {
            "magpie.user_registration_enabled": True,  # always needed, other settings added as needed per test case
            "magpie.smtp_host": "example.com",  # must exist when getting configs, but not used because email mocked
        }

        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_missing=False, raise_not_set=False)
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_missing=False, raise_not_set=False)
        cls.app = utils.get_test_magpie_app(settings=settings)
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.setup_admin()
        cls.login_admin()

        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-user-registration_ui-local",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-user-registration_ui-group",
                                           raise_missing=False, raise_not_set=False)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_end2end_user_registration_procedure_email_confirmed_admin_approved(self):
        """
        Validates the full workflow with all possible intermediate operation defined by the user registration procedure.

        .. seealso::
            - :ref:`proc_user_registration`
            - :meth:`test_end2end_user_registration_procedure_email_confirmed_admin_declined`

        Mocks email notifications to allow simulation of the back-and-forth operations between Magpie, the
        pending user requesting a new registration, and the administrator validating it via email links.
        """
        utils.warn_version(self, "User self-registration.", "3.13.0", skip=True)

        test_register_user = "test-func-user-registration-approved"
        test_register_email = "{}@email.com".format(test_register_user)
        utils.TestSetup.delete_TestUser(self, override_user_name=test_register_user, pending=False)
        utils.TestSetup.delete_TestUser(self, override_user_name=test_register_user, pending=True)

        utils.check_or_try_logout_user(self)

        # press 'Register' button to be redirected to form submission for new user registration
        # no form on the homepage for that button, so only send the corresponding request directly
        resp = utils.test_request(self, "GET", "/ui/register/users")
        data = {
            "user_name": test_register_user,
            "password": test_register_user,
            "confirm": test_register_user,
            "email": test_register_email,
        }

        # custom app settings for this test
        settings = {
            "magpie.user_registration_enabled": True,
            "magpie.user_registration_approval_enabled": True,
            "magpie.user_registration_notify_enabled": True,
            "magpie.user_registration_approval_email_recipient": "fake-admin@test.com",
            "magpie.user_registration_notify_email_recipient": "notify@user-registration.com",
        }

        from magpie.api.notifications import make_email_contents as real_contents  # test contents with real generation
        with utils.mocked_get_settings(settings=settings):
            with utils.mock_send_email("magpie.api.management.register.register_utils.send_email") as email_contexts:
                _, wrapped_contents, mocked_send = email_contexts

                # submit the registration form to trigger the confirmation email
                resp = utils.TestSetup.check_FormSubmit(self, previous_response=resp, form_data=data,
                                                        form_match="add_user_form", form_submit="create")
                body = utils.check_ui_response_basic_info(resp, expected_title="Magpie User Registration")
                utils.check_val_equal(mocked_send.call_count, 1,
                                      msg="Expected sent notification to user for its email validation.")
                utils.check_val_is_in("User registration successfully submitted", body)
                utils.check_val_is_in("confirm your email address", body)

                # validate the content of the email that would have been sent if not mocked
                message = real_contents(*wrapped_contents.call_args.args, **wrapped_contents.call_args.kwargs)
                msg_str = message.decode()
                confirm_url = wrapped_contents.call_args.args[-1].get("confirm_url")
                utils.check_val_is_in("To: {}".format(test_register_email), msg_str)
                utils.check_val_is_in("From: Magpie", msg_str)
                utils.check_val_is_in(confirm_url, msg_str)
                utils.check_val_true(confirm_url.startswith("http://localhost") and "/tmp/" in confirm_url,
                                     msg="Expected confirmation URL in email to be a temporary token URL.")

                # simulate user clicking the confirmation link in 'sent' email (external operation from Magpie)
                resp = utils.test_request(self, "GET", urlparse(confirm_url).path)
                body = utils.check_ui_response_basic_info(resp, 200, expected_title="Magpie User Registration")
                utils.check_val_is_in("email has been confirmed", body)

                # validate the content of the validation email that should have been sent to the administrator
                utils.check_val_equal(mocked_send.call_count, 2,
                                      msg="Expected email to have been sent to the administrator for approval.")
                approval_email = settings["magpie.user_registration_approval_email_recipient"]
                approve_url = wrapped_contents.call_args.args[-1].get("approve_url")
                decline_url = wrapped_contents.call_args.args[-1].get("decline_url")
                message = real_contents(*wrapped_contents.call_args.args, **wrapped_contents.call_args.kwargs)
                msg_str = message.decode()
                utils.check_val_is_in("To: {}".format(approval_email), msg_str)
                utils.check_val_is_in("From: Magpie", msg_str)
                utils.check_val_is_in(approve_url, msg_str)
                utils.check_val_is_in(decline_url, msg_str)
                approve_path = urlparse(approve_url).path
                decline_path = urlparse(decline_url).path

                # check that accessing the links for approve/decline as non-admin fails
                resp = utils.test_request(self, "GET", approve_path, expect_errors=True)
                utils.check_response_basic_info(resp, 401)
                resp = utils.test_request(self, "GET", decline_path, expect_errors=True)
                utils.check_response_basic_info(resp, 401)
                self.login_test_user()  # retry with another real user that is not admin
                resp = utils.test_request(self, "GET", approve_path, expect_errors=True)
                utils.check_response_basic_info(resp, 403)
                resp = utils.test_request(self, "GET", decline_path, expect_errors=True)
                utils.check_response_basic_info(resp, 403)
                self.login_admin()  # authenticate for actually approving next

                # simulate the administrator clicking the approval link in 'sent' email
                # temporary token URL that this administrator clicked should respond with successful approval
                resp = utils.test_request(self, "GET", approve_path)
                body = utils.check_ui_response_basic_info(resp, 200)
                utils.check_val_is_in("Pending user registration was successfully approved", body)

                # since the full process was completed with admin registration approval,
                # the pending user should have been converted to a complete user account
                info = utils.TestSetup.get_UserInfo(self, override_username=test_register_user)
                utils.check_val_equal(info["user_name"], test_register_user)
                utils.check_val_equal(info["email"], test_register_email)

                # completed registration process should have triggered notifications to configured email and user
                utils.check_val_equal(mocked_send.call_count, 4,  # both emails triggered one after another
                                      msg="Expected emails sent to user and notify from registration approved.")

                # verify the notification email
                email_notify = wrapped_contents.call_args_list[3]
                message = real_contents(*email_notify.args, **email_notify.kwargs)
                msg_str = message.decode()
                notify_addr = settings["magpie.user_registration_notify_email_recipient"]
                utils.check_val_is_in("To: {}".format(notify_addr), msg_str)
                utils.check_val_is_in("From: Magpie", msg_str)
                utils.check_val_is_in("user has completed registration", msg_str)
                utils.check_val_is_in(test_register_user, msg_str)
                utils.check_val_is_in(test_register_email, msg_str)

                # furthermore, the user should have received a notification email to indicate
                # to tell it its registration was accepted and completed successfully
                email_user = wrapped_contents.call_args_list[2]
                message = real_contents(*email_user.args, **email_user.kwargs)
                msg_str = message.decode()
                utils.check_val_is_in("To: {}".format(test_register_email), msg_str)
                utils.check_val_is_in("From: Magpie", msg_str)

                # validate that the new user can login in its account
                utils.check_or_try_logout_user(self)  # return to pending user not logged in
                utils.check_or_try_login_user(self, username=test_register_user, password=test_register_user,
                                              use_ui_form_submit=True)
                resp = utils.test_request(self, "GET", "/session", headers=self.json_headers, cookies=self.cookies)
                body = utils.check_response_basic_info(resp, 200)
                utils.check_val_true(body["authenticated"])
                utils.check_val_equal(body["user"]["user_name"], test_register_user)

    @runner.MAGPIE_TEST_USERS
    @runner.MAGPIE_TEST_FUNCTIONAL
    def test_end2end_user_registration_procedure_email_confirmed_admin_declined(self):
        """
        Validates the workflow of user registration procedure up to the point where the administrator declines it.

        .. seealso::
            - :ref:`proc_user_registration`
            - :meth:`test_end2end_user_registration_procedure_email_confirmed_admin_approved`

        .. note::
            Skip a few redundant validations in this case to concentrate on the *decline* aspect.
            See *approved* test case for full checks of all intermediate operations.

        Mocks email notifications to allow simulation of the back-and-forth operations between Magpie, the
        pending user requesting a new registration, and the administrator validating it via email links.
        """
        utils.warn_version(self, "User self-registration.", "3.13.0", skip=True)

        test_register_user = "test-func-user-registration-declined"
        test_register_email = "{}@email.com".format(test_register_user)
        utils.TestSetup.delete_TestUser(self, override_user_name=test_register_user, pending=False)
        utils.TestSetup.delete_TestUser(self, override_user_name=test_register_user, pending=True)

        utils.check_or_try_logout_user(self)

        # press 'Register' button to be redirected to form submission for new user registration
        # no form on the homepage for that button, so only send the corresponding request directly
        resp = utils.test_request(self, "GET", "/ui/register/users")
        data = {
            "user_name": test_register_user,
            "password": test_register_user,
            "confirm": test_register_user,
            "email": test_register_email,
        }

        # custom app settings for this test
        settings = {
            "magpie.user_registration_enabled": True,
            "magpie.user_registration_approval_enabled": True,
            "magpie.user_registration_notify_enabled": True,
            "magpie.user_registration_approval_email_recipient": "fake-admin@test.com",
            "magpie.user_registration_notify_email_recipient": "notify@user-registration.com",
        }

        from magpie.api.notifications import make_email_contents as real_contents  # test contents with real generation
        with utils.mocked_get_settings(settings=settings):
            with utils.mock_send_email("magpie.api.management.register.register_utils.send_email") as email_contexts:
                _, wrapped_contents, mocked_send = email_contexts

                # submit the registration form to trigger the confirmation email
                resp = utils.TestSetup.check_FormSubmit(self, previous_response=resp, form_data=data,
                                                        form_match="add_user_form", form_submit="create")
                utils.check_ui_response_basic_info(resp, expected_title="Magpie User Registration")
                utils.check_val_equal(mocked_send.call_count, 1,
                                      msg="Expected sent notification to user for its email validation.")

                # simulate user clicking the confirmation link in 'sent' email (external operation from Magpie)
                confirm_url = wrapped_contents.call_args.args[-1].get("confirm_url")
                resp = utils.test_request(self, "GET", urlparse(confirm_url).path)
                body = utils.check_ui_response_basic_info(resp, 200, expected_title="Magpie User Registration")
                utils.check_val_is_in("email has been confirmed", body)

                # retrieve the decline endpoint from the 'sent' email and authenticate as admin
                # simulate the administrator clicking the decline link to suppress the pending approval
                utils.check_val_equal(mocked_send.call_count, 2,
                                      msg="Expected email to have been sent to the administrator for approval.")
                decline_url = wrapped_contents.call_args.args[-1].get("decline_url")
                decline_path = urlparse(decline_url).path
                self.login_admin()  # admin needed for decline link
                resp = utils.test_request(self, "GET", decline_path)
                body = utils.check_ui_response_basic_info(resp, 200)
                utils.check_val_is_in("Pending user registration was successfully declined", body)
                utils.check_val_equal(
                    mocked_send.call_count, 3,  # not 4 like in other test (to user: approved + to admin: notify)
                    msg="Pending user notify email to administrator to indicate completed user registration process "
                        "should not be sent since user was declined, but email to that declined user should be sent."
                )

                # verify the declined email
                email_decline = wrapped_contents.call_args_list[2]
                message = real_contents(*email_decline.args, **email_decline.kwargs)
                msg_str = message.decode()
                utils.check_val_is_in("To: {}".format(test_register_email), msg_str)
                utils.check_val_is_in("From: Magpie", msg_str)
                utils.check_val_is_in("Magpie User Registration Declined", msg_str)

                # validate that there is not a new user, and that pending user was removed
                path = "/users/{}".format(test_register_user)
                resp = utils.test_request(self, "GET", path, expect_errors=True,
                                          headers=self.json_headers, cookies=self.cookies)
                utils.check_response_basic_info(resp, 404)
                resp = utils.test_request(self, "GET", "/register" + path, expect_errors=True,
                                          headers=self.json_headers, cookies=self.cookies)
                utils.check_response_basic_info(resp, 404)

    @runner.MAGPIE_TEST_USERS
    def test_user_pending_status(self):
        """
        Verify status of pending user is correctly displayed in applicable pages.
        """
        utils.warn_version(self, "User self-registration.", "3.13.0", skip=True)

        test_register_user = "test-user-pending-status"
        test_register_email = "{}@email.com".format(test_register_user)
        utils.TestSetup.delete_TestUser(self, override_user_name=test_register_user, pending=False)
        utils.TestSetup.delete_TestUser(self, override_user_name=test_register_user, pending=True)
        utils.TestSetup.delete_TestUser(self)

        with utils.mocked_get_settings():
            with utils.mock_send_email("magpie.api.management.register.register_utils.send_email"):
                data = {
                    "user_name": test_register_user,
                    "password": test_register_user,
                    "confirm": test_register_user,
                    "email": test_register_email,
                }
                utils.TestSetup.create_TestUser(self, override_data=data, pending=True)
                utils.TestSetup.create_TestUser(self, pending=False)

                # check that both 'normal' user and pending ones are displayed at the same time in the user list
                resp = utils.test_request(self, "GET", "/ui/users")
                body = utils.check_ui_response_basic_info(resp)
                utils.check_val_is_in(test_register_user, body)
                utils.check_val_is_in(self.test_user_name, body)

                # validate their status are correctly associated
                # FIXME

                # validate that pending user can be viewed directly in a detail page<
                path = "/ui/register/users/{}".format(test_register_user)
                resp = utils.test_request(self, "GET", path)
                body = utils.check_ui_response_basic_info(resp)
                utils.check_val_is_in(test_register_user, body)


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieUI_NoAuth_Remote(ti.Interface_MagpieUI_NoAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that do not require any AuthN/AuthZ (``MAGPIE_ANONYMOUS_GROUP`` & ``MAGPIE_ANONYMOUS_USER``).

    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.version = utils.TestSetup.get_Version(cls)
        # note: admin credentials to setup data on test instance as needed, but not to be used for these tests
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_missing=False, raise_not_set=False)
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_missing=False, raise_not_set=False)
        cls.setup_admin()
        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-no-auth_ui-user-remote",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-no-auth_ui-group-remote",
                                           raise_missing=False, raise_not_set=False)
        cls.test_service_type = ServiceWPS.service_type
        cls.test_service_name = "magpie-unittest-service-wps"


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieUI_UsersAuth_Remote(ti.Interface_MagpieUI_UsersAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require logged AuthN/AuthZ, but lower than ``MAGPIE_ADMIN_GROUP``.

    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_missing=False, raise_not_set=False)
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_missing=False, raise_not_set=False)
        cls.setup_admin()
        cls.login_admin()
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-user-auth_ui-user-remote",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-user-auth_ui-group-remote",
                                           raise_missing=False, raise_not_set=False)


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieUI_AdminAuth_Remote(ti.Interface_MagpieUI_AdminAuth, unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that require at least ``MAGPIE_ADMIN_GROUP`` AuthN/AuthZ.

    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_missing=False, raise_not_set=False)
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_missing=False, raise_not_set=False)
        cls.url = get_constant("MAGPIE_TEST_REMOTE_SERVER_URL")
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(cls.grp)
        cls.setup_admin()
        cls.login_admin()
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_user_name = get_constant("MAGPIE_TEST_USER", default_value="unittest-admin-auth_ui-user-remote",
                                          raise_missing=False, raise_not_set=False)
        cls.test_group_name = get_constant("MAGPIE_TEST_GROUP", default_value="unittest-admin-auth_ui-group-remote",
                                           raise_missing=False, raise_not_set=False)
        cls.test_service_type = ServiceAPI.service_type
        cls.test_service_name = "magpie-unittest-ui-admin-remote-service"
