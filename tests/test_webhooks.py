#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_webhooks
----------------------------------

Tests for the webhooks implementation
"""
import tempfile
import unittest
from time import sleep
import yaml

import requests

from magpie.api.schemas import UserWebhookErrorStatus
from magpie.api.webhooks import WEBHOOK_CREATE_USER_ACTION, WEBHOOK_DELETE_USER_ACTION
from magpie.constants import get_constant
from magpie.utils import CONTENT_TYPE_JSON
from tests import runner, utils

BASE_WEBHOOK_URL = "http://localhost:8080"


@runner.MAGPIE_TEST_WEBHOOKS
@runner.MAGPIE_TEST_LOCAL
class TestWebhooks(unittest.TestCase):
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

        cls.json_headers = {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON}
        cls.extra_user_names = set()

    def tearDown(self):
        """
        Cleans up the test user after a test
        """
        utils.check_or_try_logout_user(self)
        self.headers, self.cookies = utils.check_or_try_login_user(self.app, self.usr, self.pwd,
                                                                   use_ui_form_submit=True)
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestGroup(self)

    def setup_webhook_test(self, config_path):
        """
        Prepares a Magpie app using a specific testing config for webhooks
        :param config_path: path to the config file containing the webhook configs
        """
        self.app = utils.get_test_magpie_app({"magpie.config_path": config_path})
        self.headers, self.cookies = utils.check_or_try_login_user(self.app, self.usr, self.pwd,
                                                                   use_ui_form_submit=True)

        # Make sure the test user doesn't already exists from a previous test
        utils.TestSetup.delete_TestUser(self)
        utils.TestSetup.delete_TestGroup(self)

    def test_Webhook_CreateUser(self):
        """
        Test creating a user using webhooks.
        """
        # Write temporary config for testing webhooks
        create_webhook_url = BASE_WEBHOOK_URL + "/webhook_create"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WEBHOOK_CREATE_USER_ACTION,
                    "method": "POST",
                    "url": create_webhook_url,
                    "payload": {"user_name": "{user_name}", "tmp_url": "{tmp_url}"}
                },
                {
                    "name": "test_webhook_2",
                    "action": WEBHOOK_CREATE_USER_ACTION,
                    "method": "POST",
                    "url": create_webhook_url,
                    "payload": {"user_name": "{user_name}", "tmp_url": "{tmp_url}"}
                }
            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)

            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)

            utils.get_test_webhook_app(BASE_WEBHOOK_URL)

            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Wait for the webhook requests to complete
            sleep(1)

            # Check if both webhook requests have completed successfully
            resp = requests.get(BASE_WEBHOOK_URL + "/get_status")
            assert resp.text == "2"

            # Check if user creation was successful
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

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

    # Skip this test, until tmp_url is implemented
    @unittest.skip("implement tmp_url")
    def test_Webhook_CreateUser_FailingWebhook(self):
        """
        Test creating a user where the webhook receives an internal error.
        This should trigger a callback to Magpie using the tmp_url.
        """
        # Write temporary config for testing webhooks
        webhook_fail_url = BASE_WEBHOOK_URL + "/webhook_fail"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WEBHOOK_CREATE_USER_ACTION,
                    "method": "POST",
                    "url": webhook_fail_url,
                    "payload": {"user_name": "{user_name}", "tmp_url": "{tmp_url}"}
                }

            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.setup_webhook_test(webhook_tmp_config.name)

            utils.get_test_webhook_app(BASE_WEBHOOK_URL)

            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Wait for the webhook requests to complete
            sleep(1)

            # Check if user creation was successful even if the webhook resulted in failure
            users = utils.TestSetup.get_RegisteredUsersList(self)
            utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

            # Check if the user's status is set to 0
            path = "/users/{usr}".format(usr=self.test_user_name)
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            info = utils.TestSetup.get_UserInfo(self, override_body=body)
            utils.check_val_equal(info["status"], UserWebhookErrorStatus)

    def test_Webhook_CreateUser_NonExistentWebhookUrl(self):
        """
        Test creating a user where the webhook config has a non existent url
        """
        # Write temporary config for testing webhooks
        webhook_url = BASE_WEBHOOK_URL + "/non_existent"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WEBHOOK_CREATE_USER_ACTION,
                    "method": "POST",
                    "url": webhook_url,
                    "payload": {"user_name": "{user_name}", "tmp_url": "{tmp_url}"}
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
            path = "/users/{usr}".format(usr=self.test_user_name)
            resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
            body = utils.check_response_basic_info(resp, 200, expected_method="GET")
            info = utils.TestSetup.get_UserInfo(self, override_body=body)
            utils.check_val_equal(info["status"], UserWebhookErrorStatus)

    def test_Webhook_DeleteUser(self):
        """
        Test deleting a user using webhooks.
        """
        # Write temporary config for testing webhooks
        delete_webhook_url = BASE_WEBHOOK_URL + "/webhook_delete"
        data = {
            "webhooks": [
                {
                    "name": "test_webhook",
                    "action": WEBHOOK_DELETE_USER_ACTION,
                    "method": "POST",
                    "url": delete_webhook_url,
                    "payload": {"user_name": "{user_name}"}
                },
                {
                    "name": "test_webhook_2",
                    "action": WEBHOOK_DELETE_USER_ACTION,
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

            utils.get_test_webhook_app(BASE_WEBHOOK_URL)
            # create the test user first
            utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

            # Webhooks shouldn't have been called during the user creation
            sleep(1)
            resp = requests.get(BASE_WEBHOOK_URL + "/get_status")
            assert resp.text == "0"

            # delete the test user, webhooks should be called during this delete request
            path = "/users/{usr}".format(usr=self.test_user_name)
            resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
            utils.check_response_basic_info(resp, 200, expected_method="GET")
            utils.TestSetup.check_NonExistingTestUser(self)

            # Wait for the webhook requests to complete and check their success
            sleep(1)
            resp = requests.get(BASE_WEBHOOK_URL + "/get_status")
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
                    "action": WEBHOOK_CREATE_USER_ACTION,
                    "method": "POST",
                    "url": create_webhook_url,
                    "payload": {"user_name": "{user_name}", "tmp_url": "{tmp_url}"}
                }
            ],
            "providers": "",
            "permissions": ""
        }

        with tempfile.NamedTemporaryFile(mode="w") as webhook_tmp_config:
            yaml.safe_dump(data, webhook_tmp_config, default_flow_style=False)
            # create the magpie app with the test webhook config
            self.assertRaises(ValueError,  utils.get_test_magpie_app, {"magpie.config_path": webhook_tmp_config.name})
