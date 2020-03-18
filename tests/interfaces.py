import unittest
import warnings
from abc import ABCMeta
from copy import deepcopy
from distutils.version import LooseVersion
from typing import TYPE_CHECKING

import mock
import pyramid.testing
import pytest
import six
import yaml
from six.moves.urllib.parse import urlparse

from magpie.api.schemas import SwaggerGenerator
from magpie.constants import get_constant
from magpie.models import RESOURCE_TYPE_DICT, Route
from magpie.permissions import Permission
from magpie.services import SERVICE_TYPE_DICT, ServiceAccess, ServiceAPI, ServiceTHREDDS
from magpie.utils import CONTENT_TYPE_JSON, get_twitcher_protected_service_url
from tests import runner, utils

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import CookiesType, HeadersType, Optional, Str


# don't use 'unittest.TestCase' base
# some test runner raise (ERROR) the 'NotImplementedError' although overridden by other classes
class Base_Magpie_TestCase(object):
    # pylint: disable=C0103,invalid-name
    version = None              # type: Optional[Str]
    grp = None                  # type: Optional[Str]
    usr = None                  # type: Optional[Str]
    pwd = None                  # type: Optional[Str]
    require = None              # type: Optional[Str]
    cookies = None              # type: Optional[CookiesType]
    headers = None              # type: Optional[HeadersType]
    json_headers = None         # type: Optional[HeadersType]
    test_service_type = None    # type: Optional[Str]
    test_service_name = None    # type: Optional[Str]
    test_user = None            # type: Optional[Str]
    test_group = None           # type: Optional[Str]

    __test__ = False    # won't run this as a test suite, only its derived classes that overrides to True

    @classmethod
    def setUpClass(cls):  # noqa: N802
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls):  # noqa: N802
        pyramid.testing.tearDown()


@runner.MAGPIE_TEST_API
class Interface_MagpieAPI_NoAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that do not require user AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError

    @runner.MAGPIE_TEST_LOGIN
    def test_GetSession_Anonymous(self):
        resp = utils.test_request(self, "GET", "/session", headers=self.json_headers)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], False)
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_not_in("user", body)
        else:
            utils.check_val_not_in("user_name", body)
            utils.check_val_not_in("user_email", body)
            utils.check_val_not_in("group_names", body)

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
    def test_GetCurrentUser(self):
        logged_user = get_constant("MAGPIE_LOGGED_USER")
        resp = utils.test_request(self, "GET", "/users/{}".format(logged_user), headers=self.json_headers)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_equal(body["user"]["user_name"], self.usr)
        else:
            utils.check_val_equal(body["user_name"], self.usr)

    def test_NotAcceptableRequest(self):
        utils.warn_version(self, "Unsupported 'Accept' header returns 406 directly.", "0.10.0", skip=True)
        for path in ["/", "/users/current"]:
            resp = utils.test_request(self, "GET", path, expect_errors=True,
                                      headers={"Accept": "application/pdf"})  # anything not supported
            utils.check_response_basic_info(resp, expected_code=406)


@unittest.skip("Not implemented.")
@pytest.mark.skip(reason="Not implemented.")
@runner.MAGPIE_TEST_API
class Interface_MagpieAPI_UsersAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that require at least 'Users' group AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
    """

    @classmethod
    def setUpClass(cls):
        raise NotImplementedError


@runner.MAGPIE_TEST_API
class Interface_MagpieAPI_AdminAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie API. Test any operation that require at least 'administrator' group
    AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
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
        headers, cookies = utils.check_or_try_login_user(cls, cls.usr, cls.pwd,
                                                         use_ui_form_submit=True, version=cls.version)
        assert headers and cookies, cls.require             # nosec
        assert cls.headers and cls.cookies, cls.require     # nosec

    @classmethod
    def setup_test_values(cls):
        services_cfg = yaml.safe_load(open(get_constant("MAGPIE_PROVIDERS_CONFIG_PATH"), "r"))
        provider_services_info = services_cfg["providers"]
        # filter impossible providers from possible previous version of remote server
        possible_service_types = utils.get_service_types_for_version(cls.version)
        cls.test_services_info = dict()
        for svc_name in provider_services_info:
            if provider_services_info[svc_name]["type"] in possible_service_types:
                cls.test_services_info[svc_name] = provider_services_info[svc_name]

        cls.test_service_name = u"magpie-unittest-service-api"
        cls.test_service_type = ServiceAPI.service_type
        cls.test_service_perm = SERVICE_TYPE_DICT[cls.test_service_type].permissions[0].value
        utils.TestSetup.create_TestService(cls)

        cls.test_resource_name = u"magpie-unittest-resource"
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

        cls.test_group_name = u"magpie-unittest-dummy-group"
        cls.test_user_name = u"magpie-unittest-toto"
        cls.test_user_group = u"users"

    def setUp(self):
        self.check_requirements()
        utils.TestSetup.delete_TestServiceResource(self)
        utils.TestSetup.delete_TestService(self)
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestGroup(self)

    def test_GetAPI(self):
        resp = utils.test_request(self, "GET", SwaggerGenerator.path, headers=self.json_headers)
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
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_is_in("user", body)
            utils.check_val_equal(body["user"]["user_name"], self.usr)
            utils.check_val_is_in(get_constant("MAGPIE_ADMIN_GROUP"), body["user"]["group_names"])
            utils.check_val_type(body["user"]["group_names"], list)
            utils.check_val_is_in("email", body["user"])
        else:
            utils.check_val_equal(body["user_name"], self.usr)
            utils.check_val_is_in(get_constant("MAGPIE_ADMIN_GROUP"), body["group_names"])
            utils.check_val_type(body["group_names"], list)
            utils.check_val_is_in("user_email", body)

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
    def test_GetCurrentUser(self):
        logged_user = get_constant("MAGPIE_LOGGED_USER")
        path = "/users/{}".format(logged_user)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_equal(body["user"]["user_name"], self.usr)
        else:
            utils.check_val_equal(body["user_name"], self.usr)

    @runner.MAGPIE_TEST_USERS
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
        body = utils.TestSetup.create_TestServiceResource(self, data_override={"resource_type": test_res_type})
        test_parent_res_id = body["resource"]["resource_id"]
        child_resource_name = self.test_resource_name + "-child"
        data_override = {
            "resource_name": child_resource_name,
            "resource_type": test_res_type,
            "parent_id": test_parent_res_id
        }
        body = utils.TestSetup.create_TestServiceResource(self, data_override)
        test_child_res_id = body["resource"]["resource_id"]
        anonym_usr = get_constant("MAGPIE_ANONYMOUS_USER")
        anonym_grp = get_constant("MAGPIE_ANONYMOUS_GROUP")

        perm_recur = Permission.READ.value
        perm_match = Permission.READ_MATCH.value
        data_recur = {u"permission_name": perm_recur}
        data_match = {u"permission_name": perm_match}
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
        body = utils.TestSetup.create_TestServiceResource(self, data_override=data)
        test_res_id = body["resource"]["resource_id"]

        # test permission creation
        path = "/users/{usr}/resources/{res}/permissions".format(res=test_res_id, usr=self.usr)
        data = {u"permission_name": self.test_resource_perm_name}
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
        body = utils.TestSetup.create_TestServiceResource(self, data_override=data)
        test_res_id = body["resource"]["resource_id"]

        path = "/users/{usr}/resources/{res}/permissions".format(res=test_res_id, usr=self.usr)
        data = {u"permission_name": self.test_resource_perm_name}
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
        utils.TestSetup.create_TestUser(self, override_data={"group_name": self.test_group_name})
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
                svc_type_body = body["resources"][svc_type_no_perm]
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
                    svc_perms_test_user = svc_type_body[svc_name_no_perm]["permission_names"]
                    svc_perms_only_user = set(svc_perms_test_user) - set(svc_perms_anonymous)
                    utils.check_val_equal(len(svc_perms_only_user), 0,
                                          msg="User should not have any service permissions")

        # without inherit flag, only direct user permissions are visible on service and resource
        path = "/users/{usr}/resources".format(usr=usr_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        test_service = body["resources"][svc_type][svc_name]
        utils.check_val_equal(test_service["permission_names"], [perm_svc_usr])
        utils.check_val_is_in(str(res_id), test_service["resources"])
        utils.check_val_equal(test_service["resources"][str(res_id)]["permission_names"], [perm_res_usr])

        # with inherit flag, both user and group permissions are visible on service and resource
        path = "/users/{usr}/resources?inherit=true".format(usr=usr_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies, timeout=20)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        test_service = body["resources"][svc_type][svc_name]
        utils.check_all_equal(test_service["permission_names"], [perm_svc_usr, perm_svc_grp], any_order=True)
        utils.check_val_is_in(str(res_id), test_service["resources"])
        utils.check_all_equal(test_service["resources"][str(res_id)]["permission_names"],
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
                svc_dict = body["resources"][svc_type][svc]
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
                svc_dict = services[svc_type][svc]
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
        utils.check_val_equal(body["service"]["resources"][str(res_id)]["permission_names"], [perm_res_usr])

        # with inherit flag, both user and group permissions are visible on service and resource
        path = "/users/{usr}/services/{svc}/resources?inherit=true".format(usr=usr_name, svc=svc_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["service"]["service_name"], svc_name)
        utils.check_val_equal(body["service"]["service_type"], svc_type)
        utils.check_all_equal(body["service"]["permission_names"], [perm_svc_usr, perm_svc_grp], any_order=True)
        utils.check_val_is_in(str(res_id), body["service"]["resources"])
        utils.check_all_equal(body["service"]["resources"][str(res_id)]["permission_names"],
                              [perm_res_usr, perm_res_grp], any_order=True)

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers(self):
        body = utils.TestSetup.create_TestUser(self)
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_is_in("user", body)
            utils.check_val_is_in("user_name", body["user"])
            utils.check_val_type(body["user"]["user_name"], six.string_types)
            utils.check_val_is_in("email", body["user"])
            utils.check_val_type(body["user"]["email"], six.string_types)
            utils.check_val_is_in("group_names", body["user"])
            utils.check_val_type(body["user"]["group_names"], list)

        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(self.test_user_name, users)

    @runner.MAGPIE_TEST_USERS
    def test_PostUsers_ReservedKeyword_Current(self):
        data = {
            "user_name": get_constant("MAGPIE_LOGGED_USER"),
            "password": "pwd",
            "email": "email@mail.com",
            "group_name": "users",
        }
        resp = utils.test_request(self, "POST", "/users", data=data,
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method="POST")

    @runner.MAGPIE_TEST_USERS
    def test_PutUser_ReservedKeyword_Current(self):
        utils.TestSetup.create_TestUser(self)
        path = "/users/{usr}".format(usr=get_constant("MAGPIE_LOGGED_USER"))
        data = {"user_name": self.test_user_name + "-new-put-over-current"}
        resp = utils.test_request(self, "PUT", path, data=data,
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method="PUT")

    @runner.MAGPIE_TEST_USERS
    def test_PutUsers_nothing(self):
        utils.TestSetup.create_TestUser(self)
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "PUT", path, data={},
                                  headers=self.json_headers, cookies=self.cookies, expect_errors=True)
        utils.check_response_basic_info(resp, 400, expected_method="PUT")

    @runner.MAGPIE_TEST_USERS
    def test_PutUsers_username(self):
        utils.TestSetup.create_TestUser(self)
        new_name = self.test_user_name + "-new"

        # cleanup in case the updated username already exists (ex: previous test execution failure)
        utils.TestSetup.delete_TestUser(self, override_user_name=new_name)

        # update existing user name
        data = {"user_name": new_name}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "PUT", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 200, expected_method="PUT")

        # validate change of user name
        path = "/users/{usr}".format(usr=new_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["user"]["user_name"], new_name)

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
        utils.check_val_equal(body["user"]["user_name"], new_name)

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
    def test_PutUsers_email(self):
        utils.TestSetup.create_TestUser(self)
        new_email = "toto@new-email.lol"
        data = {"email": new_email}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "PUT", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 200, expected_method="PUT")

        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["user"]["email"], new_email)

    @runner.MAGPIE_TEST_USERS
    def test_PutUsers_password(self):
        utils.TestSetup.create_TestUser(self)
        old_password = self.test_user_name
        new_password = "n0t-SO-ez-2-Cr4cK"  # nosec
        data = {"password": new_password}
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "PUT", path, headers=self.json_headers, cookies=self.cookies, data=data)
        utils.check_response_basic_info(resp, 200, expected_method="PUT")
        utils.check_or_try_logout_user(self)

        # validate that the new password is effective
        headers, cookies = utils.check_or_try_login_user(
            self, username=self.test_user_name, password=new_password,
            use_ui_form_submit=True, version=self.version)
        resp = utils.test_request(self, "GET", "/session", headers=headers, cookies=cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_equal(body["authenticated"], True)
        utils.check_val_equal(body["user"]["user_name"], self.test_user_name)
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
        utils.TestSetup.create_TestUser(self)

        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_is_in("user", body)
            utils.check_val_is_in("user_name", body["user"])
            utils.check_val_type(body["user"]["user_name"], six.string_types)
            utils.check_val_is_in("email", body["user"])
            utils.check_val_type(body["user"]["email"], six.string_types)
            utils.check_val_is_in("group_names", body["user"])
            utils.check_val_type(body["user"]["group_names"], list)
        else:
            utils.check_val_is_in("user_name", body)
            utils.check_val_type(body["user_name"], six.string_types)
            utils.check_val_is_in("email", body)
            utils.check_val_type(body["email"], six.string_types)
            utils.check_val_is_in("group_names", body)
            utils.check_val_type(body["group_names"], list)

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
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.assign_TestUserGroup(self)
        utils.TestSetup.check_UserIsGroupMember(self)

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
    def test_GetUserGroups(self):
        utils.TestSetup.create_TestUser(self)   # automatically adds user to "MAGPIE_USERS_GROUP"
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.assign_TestUserGroup(self)

        path = "/users/{usr}/groups".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers,
                                  cookies=self.cookies, expect_errors=True)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.check_val_is_in("group_names", body)
        utils.check_val_type(body["group_names"], list)
        expected_groups = {self.test_group_name, self.test_user_group}
        if LooseVersion(self.version) >= LooseVersion("1.4.0"):
            expected_groups.add(get_constant("MAGPIE_ANONYMOUS_GROUP"))
        utils.check_all_equal(body["group_names"], expected_groups, any_order=True)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser(self):
        utils.TestSetup.create_TestUser(self)
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.TestSetup.check_NonExistingTestUser(self)

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUser_not_found(self):
        path = "/users/magpie-unittest-random-user"
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies,
                                  expect_errors=True)
        utils.check_response_basic_info(resp, 404, expected_method="DELETE")

    @runner.MAGPIE_TEST_USERS
    def test_DeleteUserGroup(self):
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestGroup(self)
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
    def test_PostGroups(self):
        utils.TestSetup.delete_TestGroup(self)  # setup as required
        utils.TestSetup.create_TestGroup(self)  # actual test
        utils.TestSetup.delete_TestGroup(self)  # cleanup

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
        utils.TestSetup.create_TestUser(self)
        utils.TestSetup.create_TestGroup(self)
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
        utils.check_val_type(body["group"]["description"], six.string_types)
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
            utils.TestSetup.delete_TestUser(self, override_user_name=user_name)  # clean other test runs
            utils.TestSetup.create_TestUser(self, override_data={"user_name": user_name})
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
        path = "/groups/magpie-unittest-random-group/users"
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
                svc_dict = services[svc_type][svc]
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
    def test_PostService_ResponseFormat(self):
        body = utils.TestSetup.create_TestService(self)
        utils.check_val_is_in("service", body)
        utils.check_val_type(body["service"], dict)
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
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", body["service"])
            utils.check_val_type(body["service"]["service_sync_type"], utils.OptionalStringType)

    @runner.MAGPIE_TEST_SERVICES
    def test_PutService_UpdateSuccess(self):
        body = utils.TestSetup.create_TestService(self)
        service = body["service"]
        new_svc_name = service["service_name"] + "-updated"
        new_svc_url = service["service_url"] + "/updated"
        utils.TestSetup.delete_TestService(self, override_service_name=new_svc_name)
        path = "/services/{svc}".format(svc=service["service_name"])
        data = {"service_name": new_svc_name, "service_url": new_svc_url}
        resp = utils.test_request(self, "PUT", path, data=data, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, expected_method="PUT")
        utils.check_val_is_in("service", body)
        utils.check_val_type(body["service"], dict)
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
        if LooseVersion(self.version) >= LooseVersion("0.7.0"):
            utils.check_val_is_in("service_sync_type", body["service"])
            utils.check_val_type(body["service"]["service_sync_type"], utils.OptionalStringType)
        utils.check_val_equal(body["service"]["service_url"], new_svc_url)
        utils.check_val_equal(body["service"]["service_name"], new_svc_name)

    @runner.MAGPIE_TEST_SERVICES
    def test_PutService_UpdateConflict(self):
        body = utils.TestSetup.create_TestService(self)
        service = body["service"]
        new_svc_name = service["service_name"] + "-updated"
        new_svc_url = service["service_url"] + "/updated"
        try:
            utils.TestSetup.create_TestService(self, override_service_name=new_svc_name)
            path = "/services/{svc}".format(svc=service["service_name"])
            data = {"service_name": new_svc_name, "service_url": new_svc_url}
            resp = utils.test_request(self, "PUT", path, data=data, expect_errors=True,
                                      headers=self.json_headers, cookies=self.cookies)
            utils.check_response_basic_info(resp, 409, expected_method="PUT")
        finally:
            utils.TestSetup.delete_TestService(self, override_service_name=new_svc_name)

    @runner.MAGPIE_TEST_SERVICES
    def test_PutService_NoUpdateInfo(self):
        # no path PUT on '/services/types' (not equivalent to '/services/{service_name}')
        # so not even a forbidden case to handle
        resp = utils.test_request(self, "PUT", "/services/types", data={}, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        if LooseVersion(self.version) >= LooseVersion("0.9.5"):
            # directly interpreted as expected path `/services/types` behaviour, so method PUT not allowed
            utils.check_response_basic_info(resp, 405, expected_method="PUT")
        else:
            # no path with service named 'types', filtered as not found
            utils.check_response_basic_info(resp, 404, expected_method="PUT")

    @runner.MAGPIE_TEST_SERVICES
    def test_PutService_ReservedKeyword_Types(self):
        # try to PUT on 'types' path should raise the error
        data = {"service_name": "dummy", "service_url": "dummy"}
        resp = utils.test_request(self, "PUT", "/services/types", data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        if LooseVersion(self.version) >= LooseVersion("0.9.5"):
            # directly interpreted as expected path `/services/types` behaviour, so method PUT not allowed
            utils.check_response_basic_info(resp, 405, expected_method="PUT")
        else:
            # no path with service named 'types', filtered as not found
            utils.check_response_basic_info(resp, 404, expected_method="PUT")

        utils.warn_version(self, "check for update service named 'types'", "0.9.1", skip=True)
        # try to PUT on valid service with new name 'types' should raise the error
        utils.TestSetup.create_TestService(self)
        path = "/services/{}".format(self.test_service_name)
        data = {"service_name": "types"}
        resp = utils.test_request(self, "PUT", path, data=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 400, expected_method="PUT")   # don't allow naming to 'types'

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
        for rt in body["resource_types"]:
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
            for r in body["resource_types"]:
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
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_is_in("resource", body)
            body = body["resource"]
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
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_is_in("resource", body)
            body = body["resource"]
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
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            test_resource_id = body["resource"]["resource_id"]
        else:
            test_resource_id = body["resource_id"]
        utils.check_val_is_in(test_resource_id, resources_ids,
                              msg="service resource must exist to create child resource")

        # create the child resource under the direct resource and validate response info
        child_resource_name = self.test_resource_name + "-children"
        data_override = {
            "resource_name": child_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": test_resource_id
        }
        body = utils.TestSetup.create_TestServiceResource(self, data_override)
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            utils.check_val_is_in("resource", body)
            utils.check_val_type(body["resource"], dict)
            body = body["resource"]
        utils.check_val_is_in("resource_id", body)
        utils.check_val_not_in(body["resource_id"], resources_ids)
        utils.check_val_is_in("resource_name", body)
        utils.check_val_equal(body["resource_name"], child_resource_name)
        utils.check_val_is_in("resource_type", body)
        utils.check_val_equal(body["resource_type"], self.test_resource_type)

        # validate created child resource info
        service_root_id = utils.TestSetup.get_ExistingTestServiceInfo(self)["resource_id"]
        child_resource_id = body["resource_id"]
        path = "/resources/{res_id}".format(res_id=child_resource_id)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        if LooseVersion(self.version) >= LooseVersion("0.9.2"):
            utils.check_val_is_in("resource", body)
            resource_body = body["resource"]
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
                                          param_value=self.test_resource_name, param_name=u"resource_name")

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
        services_body = body["services"]
        for svc in services_list_getcap:
            svc_name = svc["service_name"]
            svc_type = svc["service_type"]
            msg = "Service '{name}' of type '{type}' is expected to have '{perm}' permissions for user '{usr}'." \
                  .format(name=svc_name, type=svc_type, perm="getcapabilities", usr=anonymous)
            utils.check_val_is_in(svc_name, services_body[svc_type], msg=msg)
            utils.check_val_is_in("getcapabilities", services_body[svc_type][svc_name]["permission_names"])

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
        resource_info = utils.TestSetup.create_TestServiceResource(self)
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            direct_resource_id = resource_info["resource"]["resource_id"]
        else:
            direct_resource_id = resource_info["resource_id"]

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
        if LooseVersion(self.version) >= LooseVersion("0.6.3"):
            resource_id = body["resource"]["resource_id"]
        else:
            resource_id = body["resource_id"]

        path = "/resources/{res_id}".format(res_id=resource_id)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 200, expected_method="DELETE")
        utils.TestSetup.check_NonExistingTestServiceResource(self)


@runner.MAGPIE_TEST_UI
class Interface_MagpieUI_NoAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie UI. Test any operation that do not require user AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
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
        utils.TestSetup.check_Unauthorized(self, method="GET", path="/ui/users")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups(self):
        utils.TestSetup.check_Unauthorized(self, method="GET", path="/ui/groups")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServices(self):
        utils.TestSetup.check_Unauthorized(self, method="GET", path="/ui/services/default")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServicesOfType(self):
        path = "/ui/services/{}".format(self.test_service_type)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUser(self):
        path = "/ui/users/{}/default".format(self.test_user)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroup(self):
        path = "/ui/groups/{}/default".format(self.test_group)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_EditService(self):
        path = "/ui/services/{type}/{name}".format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_AddUser(self):
        path = "/ui/users/add"
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path)
        utils.TestSetup.check_Unauthorized(self, method="POST", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_AddGroup(self):
        path = "/ui/groups/add"
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path)
        utils.TestSetup.check_Unauthorized(self, method="POST", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_AddService(self):
        path = "/ui/services/{}/add".format(self.test_service_type)
        utils.TestSetup.check_Unauthorized(self, method="GET", path=path)
        utils.TestSetup.check_Unauthorized(self, method="POST", path=path)


@runner.MAGPIE_TEST_UI
class Interface_MagpieUI_AdminAuth(six.with_metaclass(ABCMeta, Base_Magpie_TestCase)):
    # pylint: disable=C0103,invalid-name
    """
    Interface class for unittests of Magpie UI. Test any operation that require at least 'administrator' group
    AuthN/AuthZ.

    Derived classes must implement ``setUpClass`` accordingly to generate the Magpie test application.
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
    def test_ViewUsers_GotoEditUser(self):
        form = {"edit": None, "user_name": self.test_user}
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path="/ui/users")
        utils.check_val_is_in("Edit User: {}".format(self.test_user), resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/groups")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewGroups_GotoEditGroup(self):
        form = {"edit": None, "group_name": self.test_group}
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path="/ui/groups")
        utils.check_val_is_in("Edit Group: {}".format(self.test_group), resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServicesDefault(self):
        utils.TestSetup.check_UpStatus(self, method="GET", path="/ui/services/default")

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServicesOfType(self):
        path = "/ui/services/{}".format(self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_ViewServices_GotoEditService(self):
        form = {"edit": None, "service_name": self.test_service_name}
        path = "/ui/services/{}".format(self.test_service_type)
        resp = utils.TestSetup.check_FormSubmit(self, form_match=form, form_submit="edit", path=path)
        find = "<span class=\"panel_value\">{}</span>".format(self.test_service_name)
        utils.check_val_is_in(find, resp.text, msg=utils.null)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUser(self):
        path = "/ui/users/{}/default".format(self.test_user)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_EditUserService(self):
        path = "/ui/users/{usr}/{type}".format(usr=self.test_user, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroup(self):
        path = "/ui/groups/{}/default".format(self.test_group)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_EditGroupService(self):
        path = "/ui/groups/{grp}/{type}".format(grp=self.test_group, type=self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_EditService(self):
        path = "/ui/services/{type}/{name}".format(type=self.test_service_type, name=self.test_service_name)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)

    @runner.MAGPIE_TEST_STATUS
    def test_AddUser(self):
        path = "/ui/users/add"
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)
        utils.TestSetup.check_UpStatus(self, method="POST", path=path)  # empty fields, same page but 'incorrect'

    @runner.MAGPIE_TEST_STATUS
    def test_AddGroup(self):
        path = "/ui/groups/add"
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)
        utils.TestSetup.check_UpStatus(self, method="POST", path=path)  # empty fields, same page but 'incorrect'

    @runner.MAGPIE_TEST_STATUS
    def test_AddService(self):
        path = "/ui/services/{}/add".format(self.test_service_type)
        utils.TestSetup.check_UpStatus(self, method="GET", path=path)
        utils.TestSetup.check_UpStatus(self, method="POST", path=path)  # empty fields, same page but 'incorrect'
