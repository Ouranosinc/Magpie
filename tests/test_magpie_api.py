#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_api
----------------------------------

Tests for :mod:`magpie.api` module.
"""
import os
import tempfile
from time import sleep
import unittest
import yaml

import mock
import requests

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti
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
        cls.check_requirements()
        cls.setup_test_values()

    def test_Webhook_CreateUser(self):
        """
        Test creating a user using multiple webhooks.
        """
        # Create temporary config for testing webhooks
        with tempfile.NamedTemporaryFile(mode='wt') as tmp_config:
            base_webhook_url = get_constant('MAGPIE_TEST_USER_WEBHOOK_URL')
            create_webhook_url = base_webhook_url + '/webhook'
            data = {
                'webhooks':
                    # Use two identical urls to simulate having multiple webhook urls
                    {'create': [create_webhook_url, create_webhook_url]}}
            yaml.dump(data, tmp_config, default_flow_style=False)

            with mock.patch.dict(os.environ, {'MAGPIE_CONFIG_PATH': tmp_config.name}):
                app = utils.get_test_webhook_app()

                utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

                # Wait for the webhook requests to complete
                sleep(1)

                # Check if both webhook requests have completed successfully
                resp = requests.get(base_webhook_url + '/get_status')
                assert resp.text == '2'

                # Check if user creation was successful
                users = utils.TestSetup.get_RegisteredUsersList(self)
                utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

    def test_Webhook_CreateUser_FailingUrl(self):
        """
        Test creating a user using a failing webhook url.
        """
        # Create temporary config for testing webhooks
        with tempfile.NamedTemporaryFile(mode='wt') as tmp_config:
            create_webhook_url = "failing_url"
            data = {'webhooks': {'create': [create_webhook_url]}}
            yaml.dump(data, tmp_config, default_flow_style=False)

            with mock.patch.dict(os.environ, {'MAGPIE_CONFIG_PATH': tmp_config.name}):
                resp = utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

                # Wait for the webhook requests to complete
                sleep(1)

                # Check if user creation was successful even if the webhook failed
                users = utils.TestSetup.get_RegisteredUsersList(self)
                utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

    def test_Webhook_CreateUser_EmptyUrl(self):
        """
        Test creating a user with an empty webhook url.
        """
        # Create temporary config for testing webhooks
        with tempfile.NamedTemporaryFile(mode='wt') as tmp_config:
            data = {'webhooks': {'create': []}}
            yaml.dump(data, tmp_config, default_flow_style=False)

            with mock.patch.dict(os.environ, {'MAGPIE_CONFIG_PATH': tmp_config.name}):
                resp = utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

                # Wait for the webhook requests to complete
                sleep(1)

                # Check if user creation was successful even if no webhook were defined in the config
                users = utils.TestSetup.get_RegisteredUsersList(self)
                utils.check_val_is_in(self.test_user_name, users, msg="Test user should exist.")

    def test_Webhook_DeleteUser(self):
        """
        Test deleting a user using multiple webhooks.
        """
        # Create temporary config for testing webhooks
        with tempfile.NamedTemporaryFile(mode='wt') as tmp_config:
            base_webhook_url = get_constant('MAGPIE_TEST_USER_WEBHOOK_URL')
            delete_webhook_url = base_webhook_url + '/webhook'
            data = {
                'webhooks':
                    # Use two identical urls to simulate having multiple webhook urls
                    {'delete': [delete_webhook_url, delete_webhook_url]}}
            yaml.dump(data, tmp_config, default_flow_style=False)

            with mock.patch.dict(os.environ, {'MAGPIE_CONFIG_PATH': tmp_config.name}):
                app = utils.get_test_webhook_app()
                # create the test user first
                utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

                # Webhooks shouldn't have been called during the user creation
                sleep(1)
                resp = requests.get(base_webhook_url + '/get_status')
                assert resp.text == '0'

                # delete the test user, webhooks should be called during this delete request
                path = "/users/{usr}".format(usr=self.test_user_name)
                resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)
                utils.check_response_basic_info(resp, 200, expected_method="GET")
                utils.TestSetup.check_NonExistingTestUser(self)

                # Wait for the webhook requests to complete and check their success
                sleep(1)
                resp = requests.get(base_webhook_url + '/get_status')
                assert resp.text == '2'

    def test_Webhook_DeleteUser_FailingUrl(self):
        """
        Test deleting a user using a failing webhook url.
        """
        # Create temporary config for testing webhooks
        with tempfile.NamedTemporaryFile(mode='wt') as tmp_config:
            delete_webhook_url = "failing_url"
            data = {'webhooks': {'delete': [delete_webhook_url]}}
            yaml.dump(data, tmp_config, default_flow_style=False)

            with mock.patch.dict(os.environ, {'MAGPIE_CONFIG_PATH': tmp_config.name}):
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
        # Create temporary config for testing webhooks
        with tempfile.NamedTemporaryFile(mode='wt') as tmp_config:
            data = {'webhooks': {'delete': []}}
            yaml.dump(data, tmp_config, default_flow_style=False)

            with mock.patch.dict(os.environ, {'MAGPIE_CONFIG_PATH': tmp_config.name}):
                # create the test user first
                utils.TestSetup.create_TestUser(self, override_group_name=get_constant("MAGPIE_ANONYMOUS_GROUP"))

                # delete the test user, webhooks should be called during the request
                path = "/users/{usr}".format(usr=self.test_user_name)
                resp = utils.test_request(self, "DELETE", path, headers=self.json_headers, cookies=self.cookies)

                # Check if user deletion was successful even if no webhooks were defined in the config
                sleep(1)
                utils.check_response_basic_info(resp, 200, expected_method="GET")
                utils.TestSetup.check_NonExistingTestUser(self)


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
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
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
    sys.exit(unittest.main())
