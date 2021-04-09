#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_webhooks
----------------------------------

Tests for the webhooks implementation
"""
import inspect
import tempfile
import unittest
from time import sleep

import requests
import yaml
from six.moves.urllib.parse import urlparse

from magpie.api.schemas import UserStatuses
from magpie.api.webhooks import WebhookAction, replace_template, webhook_update_error_status
from magpie.constants import get_constant
from magpie.permissions import Access, PermissionSet, Permission, Scope
from magpie.services import ServiceAPI
from magpie.utils import CONTENT_TYPE_HTML
from tests import interfaces as ti
from tests import runner, utils


@runner.MAGPIE_TEST_WEBHOOKS
@runner.MAGPIE_TEST_FUNCTIONAL
@runner.MAGPIE_TEST_LOCAL
class TestWebhooks(ti.BaseTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that uses webhooks.

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_group_name = "magpie-unittest-dummy-group"
        cls.test_user_name = "magpie-unittest-toto"
        cls.test_service_name = "unittest-webhook-service"
        cls.test_service_type = ServiceAPI.service_type
        cls.test_resource_name = "unittest-webhook-resource"
        cls.test_resource_type = list(ServiceAPI.resource_types_permissions.items())[0][0].resource_type_name

        # tmp app to prepare test admin access
        # discard afterwards to regenerate different configs per test
        cls.app = utils.get_test_magpie_app()
        cls.setup_admin()
        cls.login_admin()

        # cleanup in case of test stopped midway before complete cleanup
        utils.TestSetup.delete_TestService(cls)
        utils.TestSetup.delete_TestGroup(cls)
        utils.TestSetup.delete_TestUser(cls)

        cls.app = None  # reset app, recreate on each test with specific webhook config
        cls.base_webhook_url = "http://localhost:8080"

    def tearDown(self):
        """
        Cleans up the test user after a test.
        """
        # skip if app was not set for that test
        if self.app is not None:
            utils.check_or_try_logout_user(self)
            self.headers, self.cookies = utils.check_or_try_login_user(self.app, self.usr, self.pwd,
                                                                       use_ui_form_submit=True)
            utils.TestSetup.delete_TestUser(self)
            utils.TestSetup.delete_TestGroup(self)

    def setup_webhook_test(self, config_path):
        """
        Prepares a Magpie app using a specific testing config for webhooks.

        :param config_path: path to the config file containing the webhook configs
        """
        self.app = utils.get_test_magpie_app({"magpie.config_path": config_path})
        self.headers, self.cookies = utils.check_or_try_login_user(self.app, self.usr, self.pwd,
                                                                   use_ui_form_submit=True)
        # Make sure the test user doesn't already exists from a previous test
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestGroup(self)

    def checkTestUserStatus(self, status):
        # type: (UserStatuses) -> None
        """
        Checks if the test user has the expected status value.

        :param status: Status value that should be found for the test user
        """
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["status"], status.value)

    def test_Webhook_CreateUser(self):
        """
        Test creating a user using webhooks.
        """
        # Write temporary config for testing webhooks
        create_webhook_url = self.base_webhook_url + "/webhook_json"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WebhookAction.CREATE_USER.value,
                    "method": "POST",
                    "url": create_webhook_url,
                    "payload": {"user_name": "{{user.name}}", "callback_url": "{{callback_url}}"}
                },
                {
                    "name": "test_webhook_2",
                    "action": WebhookAction.CREATE_USER.value,
                    "method": "POST",
                    "url": create_webhook_url,
                    # Test with a more complex payload, that includes different types and nested arrays / dicts
                    "payload": [
                        {"user_name": ["{{user.name}}", "other_param"],
                            "nested_dict": {
                                "{{user.name}}": "{{user.name}} {{user.name}}",
                        }},
                        "{{user.name}}",
                        False,
                        1
                    ]
                }
            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)

            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)
            utils.get_test_webhook_app(self.base_webhook_url)

            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Wait for the webhook requests to complete
            sleep(1)

            # Check if the webhook received the more complex payload, with the right template replacements
            expected_payload = [{"nested_dict": {self.test_user_name: self.test_user_name + " " + self.test_user_name},
                                 "user_name": [self.test_user_name, "other_param"]},
                                self.test_user_name, False, 1]
            resp = requests.post(self.base_webhook_url + "/check_payload", json=expected_payload)
            utils.check_response_basic_info(resp, 200, expected_method="POST", expected_type=CONTENT_TYPE_HTML,
                                            extra_message=resp.text)

            # Check if both webhook requests have completed successfully
            resp = requests.get(self.base_webhook_url + "/get_status")
            utils.check_val_equal(resp.text, "2")

            # Check if user creation was successful
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")
            self.checkTestUserStatus(UserStatuses.OK)

    def test_Webhook_CreateUser_EmptyUrl(self):
        """
        Test creating a user with an empty webhook url.
        """
        # Write temporary config for testing webhooks
        data = {
            "webhooks": [],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)

            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Wait for the potential webhook requests to complete
            # In this case, there should be no webhook request to execute
            sleep(1)

            # Check if user creation was successful even if no webhook were defined in the config
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")
            self.checkTestUserStatus(UserStatuses.OK)

    def test_Webhook_CreateUser_FailingWebhook(self):
        """
        Test creating a user where the webhook receives an internal error.

        This should trigger a callback to Magpie using the callback URL.
        """
        # Write temporary config for testing webhooks
        webhook_fail_url = self.base_webhook_url + "/webhook_fail"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WebhookAction.CREATE_USER.value,
                    "method": "POST",
                    "url": webhook_fail_url,
                    "payload": {"user_name": "{{user.name}}", "callback_url": "{{callback_url}}"}
                }

            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)
            utils.get_test_webhook_app(self.base_webhook_url)

            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Wait for the webhook requests to complete
            sleep(1)

            # Check if user creation was successful even if the webhook resulted in failure
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

            # Check if the user's status is still set to 1, since the callback URL has not been called yet
            self.checkTestUserStatus(UserStatuses.OK)

            # Retrieve the callback URL and send the request to the magpie app
            resp = requests.get(self.base_webhook_url + "/get_callback_url")
            utils.check_response_basic_info(resp, 200, expected_method="GET", expected_type=CONTENT_TYPE_HTML)
            utils.check_val_true(resp.text.startswith("http://"),
                                 msg="Expected to have a valid templated URL, but got: [{}]".format(resp.text))
            utils.test_request(self, "GET", urlparse(resp.text).path)

            # Check if the user's status is set to 0
            self.checkTestUserStatus(UserStatuses.WebhookErrorStatus)

    def test_Webhook_CreateUser_NonExistentWebhookUrl(self):
        """
        Test creating a user where the webhook config has a non existent url.

        Because the webhook fails to send the request where it must, it should set the user status as error.
        """
        # Write temporary config for testing webhooks
        webhook_url = self.base_webhook_url + "/non_existent"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WebhookAction.CREATE_USER.value,
                    "method": "POST",
                    "url": webhook_url,
                    "payload": {"user_name": "{{user.name}}", "callback_url": "{{callback_url}}"}
                }

            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)
            utils.get_test_webhook_app(self.base_webhook_url)

            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Wait for the webhook requests to complete
            sleep(1)

            # Check if user creation was successful even if the webhook resulted in failure
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

            # Check if the user's status is set to 0
            self.checkTestUserStatus(UserStatuses.WebhookErrorStatus)

    def test_Webhook_DeleteUser(self):
        """
        Test deleting a user using webhooks.
        """
        # Write temporary config for testing webhooks
        delete_webhook_url = self.base_webhook_url + "/webhook_json"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WebhookAction.DELETE_USER.value,
                    "method": "POST",
                    "url": delete_webhook_url,
                    "payload": {"user_name": "{{user.name}}"}
                },
                {
                    "name": "test_webhook_2",
                    "action": WebhookAction.DELETE_USER.value,
                    "method": "POST",
                    "url": delete_webhook_url,
                    "payload": {"user_name": "{{user.name}}"}
                }
            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)
            utils.get_test_webhook_app(self.base_webhook_url)

            # create the test user first
            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Webhooks shouldn't have been called during the user creation
            sleep(1)
            resp = requests.get(self.base_webhook_url + "/get_status")
            utils.check_val_equal(resp.text, "0")

            # delete the test user, webhooks should be called during this delete request
            path = "/users/{usr}".format(usr=self.test_user_name)
            resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
            utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.TestSetup.check_NonExistingTestUser(self)

            # Wait for the webhook requests to complete and check their success
            sleep(1)
            resp = requests.get(self.base_webhook_url + "/get_status")
            assert resp.text == "2"

    def test_Webhook_DeleteUser_EmptyUrl(self):
        """
        Test deleting a user with an empty webhook url.
        """
        # Write temporary config for testing webhooks
        data = {
            "webhooks": [],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)

            # create the test user first
            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # delete the test user, webhooks should be called during the request
            path = "/users/{usr}".format(usr=self.test_user_name)
            resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)

            # Check if user deletion was successful even if no webhooks were defined in the config
            sleep(1)
            utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.TestSetup.check_NonExistingTestUser(self)

    def test_Webhook_UpdateUserStatus(self):
        update_webhook_url = self.base_webhook_url + "/webhook_json"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WebhookAction.UPDATE_USER_STATUS.value,
                    "method": "POST",
                    "url": update_webhook_url,
                    "payload": {
                        "name": "{{user.name}}",
                        "status": "{{user.status}}",
                        "callback_url": "{{callback_url}}"
                    }
                }
            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)

            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)
            utils.get_test_webhook_app(self.base_webhook_url)

            utils.TestSetup.create_TestGroup(self)
            utils.TestSetup.create_TestUser(self)
            webhook_update_error_status(self.test_user_name)  # modify the status to be invalid
            self.checkTestUserStatus(UserStatuses.WebhookErrorStatus)

            # trigger the webhook with update request
            path = "/users/{}".format(self.test_user_name)
            data = {"status": UserStatuses.OK.value}
            utils.test_request(self, "PATCH", path, json=data, headers=self.json_headers, cookies=self.cookies)

            # Wait for the webhook requests to complete and check it was received by the middleware
            sleep(1)
            resp = requests.get(self.base_webhook_url + "/get_status")
            utils.check_val_equal(resp.text, "1")
            # at this point, the user is considered valid following status update in magpie
            self.checkTestUserStatus(UserStatuses.OK)

            # simulate that the middleware operation fails, so it sends the callback request to revert status
            resp = requests.get(self.base_webhook_url + "/get_callback_url")
            callback_url = urlparse(resp.text).path
            resp = utils.test_request(self, "GET", callback_url)
            utils.check_response_basic_info(resp, 200, expected_method="GET", expected_type=None)

            # now that callback request was accomplished, use should have been reverted to bad status
            self.checkTestUserStatus(UserStatuses.WebhookErrorStatus)

    def test_Webhook_UpdatePermissions(self):
        """
        Test every combination of (user|group, service|resource, permission, created|deleted) webhook operation.
        """
        update_webhook_url = self.base_webhook_url + "/webhook_json"
        res_perm_payload = {
            param.replace(".", "_"): "{{{{{}}}}}".format(param) for param in
            ["resource.id", "resource.name", "resource.type",
             "service.name", "service.type", "service.sync_type", "service.public_url",
             "permission.name", "permission.scope", "permission.access"]
        }
        user_payload = {"user_name": "{{user.name}}", "user_id": "{{user.id}}"}
        user_payload.update(res_perm_payload)
        group_payload = {"group_name": "{{group.name}}", "group_id": "{{group.id}}"}
        group_payload.update(res_perm_payload)
        webhook_config = {
            "webhooks": [
                {
                    "name": "test_webhook_{}".format(WebhookAction.CREATE_USER_PERMISSION.value),
                    "action": WebhookAction.CREATE_USER_PERMISSION.value,
                    "method": "POST",
                    "url": update_webhook_url,
                    "payload": {"data": user_payload, "action": WebhookAction.CREATE_USER_PERMISSION.value}
                },
                {
                    "name": "test_webhook_{}".format(WebhookAction.DELETE_USER_PERMISSION.value),
                    "action": WebhookAction.DELETE_USER_PERMISSION.value,
                    "method": "POST",
                    "url": update_webhook_url,
                    "payload": {"data": user_payload, "action": WebhookAction.DELETE_USER_PERMISSION.value}
                },
                {
                    "name": "test_webhook_{}".format(WebhookAction.CREATE_GROUP_PERMISSION.value),
                    "action": WebhookAction.CREATE_GROUP_PERMISSION.value,
                    "method": "POST",
                    "url": update_webhook_url,
                    "payload": {"data": group_payload, "action": WebhookAction.CREATE_GROUP_PERMISSION.value}
                },
                {
                    "name": "test_webhook_{}".format(WebhookAction.DELETE_GROUP_PERMISSION.value),
                    "action": WebhookAction.DELETE_GROUP_PERMISSION.value,
                    "method": "POST",
                    "url": update_webhook_url,
                    "payload": {"data": group_payload, "action": WebhookAction.DELETE_GROUP_PERMISSION.value}
                }
            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(webhook_config, webhook_tmp_config, default_flow_style=False)

            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)
            utils.get_test_webhook_app(self.base_webhook_url)

            svc_id, res_id, = utils.TestSetup.create_TestServiceResourceTree(self)
            body = utils.TestSetup.create_TestGroup(self)
            info = utils.TestSetup.get_GroupInfo(self, override_body=body)
            grp_id = info["group_id"]
            body = utils.TestSetup.create_TestUser(self)
            info = utils.TestSetup.get_UserInfo(self, override_body=body)
            usr_id = info["user_id"]

            rAM = PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH)      # noqa
            wDR = PermissionSet(Permission.WRITE, Access.DENY, Scope.RECURSIVE)  # noqa

            def update_perm_and_validate_webhook(t_name, r_id, perm, action):
                """
                Trigger one of the webhooks with request and validate the corresponding result middleware payload.
                """
                # send request to magpie
                meth = "DELETE" if "delete" in action.value else "POST"
                code = 200 if meth == "DELETE" else 201
                path = "/users/{}/resources/{}/permissions".format(t_name, r_id)
                data = {"permission": perm.json()}
                resp = utils.test_request(self, meth, path, json=data, headers=self.json_headers, cookies=self.cookies)
                utils.check_response_basic_info(resp, expected_code=code, expected_method=meth)

                # check that webhook was triggered and sent to the middleware
                sleep(1)  # small delay to let webhook being processed
                resp = requests.get(self.base_webhook_url + "/get_status")
                utils.check_val_equal(resp.text, "1")

                # prepare expected payload the webhook should have sent based on templated parameters
                expected = {
                    "action": action.value,
                    "data": {}
                }
                if t_name == self.test_user_name:
                    expected["data"]["user_name"] = self.test_user_name
                    expected["data"]["user_id"] = usr_id
                else:
                    expected["data"]["group_name"] = self.test_group_name
                    expected["data"]["group_id"] = grp_id
                url = "http://localhost/twitcher/ows/proxy/{}".format(self.test_service_name)
                if r_id == res_id:
                    expected["data"]["resource_name"] = self.test_resource_name
                    expected["data"]["resource_type"] = self.test_resource_type
                    expected["data"]["resource_id"] = res_id
                    expected["data"]["service_name"] = None
                    expected["data"]["service_type"] = None
                    expected["data"]["service_public_url"] = None
                else:
                    expected["data"]["resource_name"] = self.test_service_name
                    expected["data"]["resource_type"] = "service"
                    expected["data"]["resource_id"] = svc_id
                    expected["data"]["service_name"] = self.test_service_name
                    expected["data"]["service_type"] = self.test_service_type
                    expected["data"]["service_public_url"] = url
                expected["data"]["service_sync_type"] = None
                expected["data"]["permission_name"] = perm.name.value
                expected["data"]["permission_access"] = perm.access.value
                expected["data"]["permission_scope"] = perm.scope.value

                # validate and reset for next test
                resp = requests.get(self.base_webhook_url + "/get_payload")
                utils.check_val_equal(resp.json(), expected, diff=True)
                requests.get(self.base_webhook_url + "/reset")

            # test cases
            update_perm_and_validate_webhook(self.test_user_name, res_id, rAM, WebhookAction.CREATE_USER_PERMISSION)
            update_perm_and_validate_webhook(self.test_user_name, res_id, rAM, WebhookAction.DELETE_USER_PERMISSION)
            update_perm_and_validate_webhook(self.test_user_name, res_id, wDR, WebhookAction.CREATE_USER_PERMISSION)
            update_perm_and_validate_webhook(self.test_user_name, svc_id, rAM, WebhookAction.CREATE_USER_PERMISSION)
            update_perm_and_validate_webhook(self.test_group_name, svc_id, rAM, WebhookAction.CREATE_GROUP_PERMISSION)
            update_perm_and_validate_webhook(self.test_user_name, svc_id, rAM, WebhookAction.DELETE_GROUP_PERMISSION)
            update_perm_and_validate_webhook(self.test_group_name, res_id, wDR, WebhookAction.CREATE_GROUP_PERMISSION)
            update_perm_and_validate_webhook(self.test_group_name, svc_id, rAM, WebhookAction.DELETE_GROUP_PERMISSION)
            update_perm_and_validate_webhook(self.test_user_name, svc_id, wDR, WebhookAction.CREATE_USER_PERMISSION)
            update_perm_and_validate_webhook(self.test_group_name, res_id, wDR, WebhookAction.DELETE_GROUP_PERMISSION)


# NOTE:
#   This function is also included in docs to provide a detailed and working example of substitution patterns.
#   If the name is modified or more decorators are added, docs must be updated accordingly.

@runner.MAGPIE_TEST_WEBHOOKS
@runner.MAGPIE_TEST_LOCAL
def test_webhook_template_substitution():
    """
    Verify that webhook template replacement works as expected against parameter values of different types.

    For example, a list item or dictionary value can be an integer, which should be preserved.
    If quotes are added, the non-string fields should then be converted to string as expected.
    Quotes on string fields though are redundant and should be ignored.
    Additional repeated quotes should leave them as specified.
    """
    params = {"user.name": "test", "user.id": 123}
    spec = yaml.safe_load(inspect.cleandoc("""
    payload:
      param: 
        name: "{{user.name}}"
        id: "{{user.id}}"
        id_str: "'{{user.id}}'"
        none: user.id               # only plain name, not a template substitution
        str: "{user.name}"          # literal field with '{user.name}', not a template substitution
        obj: {user.name}            # object with field 'user.name', not a template substitution
      compose:
        id: user_{{user.id}}
        msg: Hello {{user.name}}, your ID is {{user.id}}
      key_str: 
        "{{user.id}}": "id"
        "{{user.name}}": "name"
      listed: 
        - "{{user.id}}"
        - "{{user.name}}"
        - "'{{user.id}}'"
      quoted: 
        explicit: "{{user.name}}"
        single: "\'{{user.name}}\'"
        double: "\\"{{user.name}}\\""
        multi: "\\"\'\'\\"{{user.name}}\\"\'\'\\""
    """))
    expect = {
        "param": {
            "name": params["user.name"],
            "id": params["user.id"],
            "id_str": str(params["user.id"]),
            "str": "{user.name}",
            "obj": {"user.name": None},  # format is not a template, but a valid YAML definition
            "none": "user.id"  # was not a template, remains literal string not replaced by value
        },
        "compose": {
            "id": "user_{}".format(params["user.id"]),
            "msg": "Hello {}, your ID is {}".format(params["user.name"], params["user.id"])
        },
        "key_str": {
            str(params["user.id"]): "id",
            params["user.name"]: "name"
        },
        "listed": [
            params["user.id"],
            params["user.name"],
            str(params["user.id"])
        ],
        "quoted": {
            "explicit": "{}".format(params["user.name"]),
            "single": "'{}'".format(params["user.name"]),
            "double": "\"{}\"".format(params["user.name"]),
            "multi": "\"\'\'\"{}\"\'\'\"".format(params["user.name"])
        }
    }
    data = utils.check_no_raise(lambda: replace_template(params, spec["payload"]))
    utils.check_val_equal(data, expect, diff=True)


@runner.MAGPIE_TEST_WEBHOOKS
@runner.MAGPIE_TEST_LOCAL
def test_webhook_template_literal():
    """
    Verify that webhook literal string payload works as intended.
    """
    params = {"user.name": "test", "user.id": 123}
    spec = yaml.safe_load(inspect.cleandoc("""
    payload: |
      param: {{user.name}}
      quote: "{{user.id}}"
    """))
    expect = "param: {}\nquote: \"{}\"".format(params["user.name"], params["user.id"])
    data = utils.check_no_raise(lambda: replace_template(params, spec["payload"]))
    utils.check_val_equal(data, expect)


@runner.MAGPIE_TEST_WEBHOOKS
@runner.MAGPIE_TEST_LOCAL
class TestFailingWebhooks(unittest.TestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that uses an incorrect webhook config.
    """

    __test__ = True

    def test_Webhook_IncorrectConfig(self):
        """
        Test using a config with a badly formatted url.
        """
        # Write temporary config for testing webhooks
        create_webhook_url = "failing_url"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook_app",
                    "action": WebhookAction.CREATE_USER.value,
                    "method": "POST",
                    "url": create_webhook_url,
                    "payload": {"user_name": "{{user.name}}", "callback_url": "{{callback_url}}"}
                }
            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            utils.check_raises(lambda: utils.get_test_magpie_app({"magpie.config_path": webhook_tmp_config.name}),
                               ValueError, msg="Invalid URL in webhook configuration should be raised.")
