#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_webhooks
----------------------------------

Tests for the webhooks implementation
"""
import tempfile
from time import sleep
import yaml

import requests

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti
from magpie.constants import get_constant
from tests import runner, utils


@runner.MAGPIE_TEST_WEBHOOKS
@runner.MAGPIE_TEST_LOCAL
class TestWebhooks(ti.AdminTestCase):
    # pylint: disable=C0103,invalid-name
    """
    Test any operation that uses webhooks.

    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.base_webhook_url = "http://localhost:8080"
        cls.webhook_tmp_config = tempfile.NamedTemporaryFile(mode="w")
        # write default config with empty values, webhooks will be overwritten for each specific test setup
        data = {
            "webhooks": {},
            "providers": "",
            "permissions": ""
        }
        yaml.dump(data, cls.webhook_tmp_config, default_flow_style=False)
        cls.app = utils.get_test_magpie_app({"magpie.config_path": cls.webhook_tmp_config.name})
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.check_requirements()

        cls.test_group_name = "magpie-unittest-dummy-group"
        cls.test_user_name = "magpie-unittest-toto"

    @classmethod
    def tearDownClass(cls):
        cls.webhook_tmp_config.close()

    def test_Webhook_CreateUser(self):
        """
        Test creating a user using multiple webhooks.
        """
        # Write temporary config for testing webhooks
        create_webhook_url = self.base_webhook_url + "/webhook"
        data = {
            "webhooks":
                # Use two identical urls to simulate having multiple webhook urls
                {"create": [create_webhook_url, create_webhook_url]}
        }
        with open(self.webhook_tmp_config.name, 'w') as stream:
            yaml.safe_dump(data, stream, default_flow_style=False)

        utils.get_test_webhook_app(self.base_webhook_url)

        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

        # Wait for the webhook requests to complete
        sleep(1)

        # Check if both webhook requests have completed successfully
        resp = requests.get(self.base_webhook_url + "/get_status")
        assert resp.text == "2"

        # Check if user creation was successful
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

    def test_Webhook_CreateUser_FailingUrl(self):
        """
        Test creating a user using a failing webhook url.
        """
        # Write temporary config for testing webhooks
        create_webhook_url = "failing_url"
        data = {"webhooks": {"create": [create_webhook_url]}}
        with open(self.webhook_tmp_config.name, 'w') as stream:
            yaml.dump(data, stream, default_flow_style=False)

        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

        # Wait for the webhook requests to complete
        sleep(1)

        # Check if user creation was successful even if the webhook failed
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

    def test_Webhook_CreateUser_EmptyUrl(self):
        """
        Test creating a user with an empty webhook url.
        """
        # Write temporary config for testing webhooks
        data = {"webhooks": {"create": []}}
        with open(self.webhook_tmp_config.name, 'w') as stream:
            yaml.dump(data, stream, default_flow_style=False)

        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

        # Wait for the webhook requests to complete
        sleep(1)

        # Check if user creation was successful even if no webhook were defined in the config
        users = utils.TestSetup.get_RegisteredUsersList(self)
        utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

    def test_Webhook_DeleteUser(self):
        """
        Test deleting a user using multiple webhooks.
        """
        # Write temporary config for testing webhooks
        delete_webhook_url = self.base_webhook_url + "/webhook"
        data = {
            "webhooks":
                # Use two identical urls to simulate having multiple webhook urls
                {"delete": [delete_webhook_url, delete_webhook_url]}}

        with open(self.webhook_tmp_config.name, 'w') as stream:
            yaml.dump(data, stream, default_flow_style=False)

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

    def test_Webhook_DeleteUser_FailingUrl(self):
        """
        Test deleting a user using a failing webhook url.
        """
        # Write temporary config for testing webhooks
        delete_webhook_url = "failing_url"
        data = {"webhooks": {"delete": [delete_webhook_url]}}
        with open(self.webhook_tmp_config.name, 'w') as stream:
            yaml.dump(data, stream, default_flow_style=False)

        # create the test user first
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

        # delete the test user, webhooks should be called during the request
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)

        # Check if user deletion was successful even if the webhook failed
        sleep(1)
        utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.TestSetup.check_NonExistingTestUser(self)

    def test_Webhook_DeleteUser_EmptyUrl(self):
        """
        Test deleting a user with an empty webhook url.
        """
        # Write temporary config for testing webhooks
        data = {"webhooks": {"delete": []}}
        with open(self.webhook_tmp_config.name, 'w') as stream:
            yaml.dump(data, stream, default_flow_style=False)

        # create the test user first
        utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

        # delete the test user, webhooks should be called during the request
        path = "/users/{usr}".format(usr=self.test_user_name)
        resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)

        # Check if user deletion was successful even if no webhooks were defined in the config
        sleep(1)
        utils.check_response_basic_info(resp, 200, expected_method="GET")
        utils.TestSetup.check_NonExistingTestUser(self)
