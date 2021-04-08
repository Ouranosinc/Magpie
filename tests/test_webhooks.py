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
from magpie.api.webhooks import WebhookAction, replace_template
from magpie.constants import get_constant
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

        # tmp app to prepare test admin access
        # discard afterwards to regenerate different configs per test
        cls.app = utils.get_test_magpie_app()
        cls.setup_admin()
        cls.app = None

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
        """
        Checks if the test user has the expected status value.

        :param status: Status value that should be found for the test user
        """
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_UserInfo(self, override_body=body)
        utils.check_val_equal(info["status"], status)

    def test_Webhook_CreateUser(self):
        """
        Test creating a user using webhooks.
        """
        # Write temporary config for testing webhooks
        create_webhook_url = self.base_webhook_url + "/webhook_create"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WebhookAction.CREATE_USER.value,
                    "method": "POST",
                    "url": create_webhook_url,
                    "payload": {"user_name": "{user_name}", "callback_url": "{callback_url}"}
                },
                {
                    "name": "test_webhook_2",
                    "action": WebhookAction.CREATE_USER.value,
                    "method": "POST",
                    "url": create_webhook_url,
                    # Test with a more complex payload, that includes different types and nested arrays / dicts
                    "payload": [
                        {"user_name": ["{user_name}", "other_param"],
                            "nested_dict": {
                                "{user_name}": "{user_name} {user_name}",
                        }},
                        "{user_name}", False, 1
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
            assert resp.text == "2"

            # Check if user creation was successful
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")
            self.checkTestUserStatus(UserStatuses.OK.value)

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
            self.checkTestUserStatus(UserStatuses.OK.value)

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
                    "payload": {"user_name": "{user_name}", "callback_url": "{callback_url}"}
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
            self.checkTestUserStatus(UserStatuses.OK.value)

            # Retrieve the callback URL and send the request to the magpie app
            resp = requests.get(self.base_webhook_url + "/get_callback_url")
            utils.check_response_basic_info(resp, 200, expected_method="GET", expected_type=CONTENT_TYPE_HTML)
            utils.test_request(self, "GET", urlparse(resp.text).path)

            # Check if the user's status is set to 0
            self.checkTestUserStatus(UserStatuses.WebhookErrorStatus.value)

    def test_Webhook_CreateUser_NonExistentWebhookUrl(self):
        """
        Test creating a user where the webhook config has a non existent url.
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
                    "payload": {"user_name": "{user_name}", "callback_url": "{callback_url}"}
                }

            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)

            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Wait for the webhook requests to complete
            sleep(1)

            # Check if user creation was successful even if the webhook resulted in failure
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

            # Check if the user's status is set to 0
            self.checkTestUserStatus(UserStatuses.WebhookErrorStatus.value)

    def test_Webhook_DeleteUser(self):
        """
        Test deleting a user using webhooks.
        """
        # Write temporary config for testing webhooks
        delete_webhook_url = self.base_webhook_url + "/webhook_delete"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WebhookAction.DELETE_USER.value,
                    "method": "POST",
                    "url": delete_webhook_url,
                    "payload": {"user_name": "{user_name}"}
                },
                {
                    "name": "test_webhook_2",
                    "action": WebhookAction.DELETE_USER.value,
                    "method": "POST",
                    "url": delete_webhook_url,
                    "payload": {"user_name": "{user_name}"}
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
            assert resp.text == "0"

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


@runner.MAGPIE_TEST_WEBHOOKS
@runner.MAGPIE_TEST_LOCAL
def test_webhook_template_substitution():
    """
    Verify that webhook template replacement works as expected against parameter values of different types.

    For example, a list item or dictionary value can be an class:`int`, which should be preserved.
    If quotes are added, the class:`int` fields is then converted to string as expected.
    Quotes on string fields though are redundant and should be ignored.
    Additional repeated quotes should leave them as specified.
    """
    params = {"user_name": "test", "user_id": 123}
    spec = yaml.safe_load(inspect.cleandoc("""
    payload:
      param: 
        name: "{{user_name}}"
        id: "{{user_id}}"
        id_str: "'{{user_id}}'"
        none: user_id               # not template, only plain name 
        str: "{user_name}"          # literal field with '{user_name}'
        obj: {user_name}            # object with field 'user_name'
      compose:
        id: user_{{user_id}}
        msg: Hello {{user_name}}, your ID is {{user_id}}
      key_str: 
        "{{user_id}}": "id"
        "{{user_name}}": "name"
      listed: 
        - "{{user_id}}"
        - "{{user_name}}"
        - "'{{user_id}}'"
      quoted: 
        explicit: "{{user_name}}"
        single: "\'{{user_name}}\'"
        double: "\\"{{user_name}}\\""
        multi: \\"\\'\\'\\"{{user_name}}\\"\\'\\'\\"
    """))
    expect = {
        "param": {
            "name": params["user_name"],
            "id": params["user_id"],
            "id_str": str(params["user_id"]),
            "str": "{user_name}",
            "obj": {"user_name": None},  # format is not a template, but a valid YAML definition
            "none": "user_id"  # was not a template, remains literal string not replaced by value
        },
        "compose": {
            "id": "user_{}".format(params["user_id"]),
            "msg": "Hello {}, your ID is {}".format(params["user_name"], params["user_id"])
        },
        "key_str": {
            str(params["user_id"]): "id",
            params["user_name"]: "name"
        },
        "listed": [
            params["user_id"],
            params["user_name"],
            str(params["user_id"])
        ],
        "quoted": {
            "explicit": "{}".format(params["user_name"]),
            "single": "'{}'".format(params["user_name"]),
            "double": "\"{}\"".format(params["user_name"]),
            "multi": "\"\'\'\"{}\"\'\'\"".format(params["user_name"])
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
    params = {"user_name": "test", "user_id": 123}
    spec = yaml.safe_load(inspect.cleandoc("""
    payload: |
      param: {{user_name}}
      quote: "{{user_id}}"
    """))
    expect = "param: {}\nquote: \"{}\"".format(params["user_name"], params["user_id"])
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
                    "payload": {"user_name": "{user_name}", "callback_url": "{callback_url}"}
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
