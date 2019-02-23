#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_ui
----------------------------------

Tests for `magpie.ui` module.
"""

from magpie.common import JSON_TYPE
from magpie.constants import get_constant
from tests import utils, runner
import unittest

# NOTE: must be imported without 'from', otherwise the interface's test cases are also executed
import tests.interfaces as ti
import unittest


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieUI_NoAuth_Local(ti.Interface_MagpieUI_NoAuth, unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.json_headers = utils.get_headers(cls.app, {'Accept': JSON_TYPE, 'Content-Type': JSON_TYPE})
        cls.cookies = None
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = 'wps'
        cls.test_service_name = 'flyingpigeon'


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_LOCAL
class TestCase_MagpieUI_AdminAuth_Local(ti.Interface_MagpieUI_AdminAuth, unittest.TestCase):
    """
    Test any operation that require at least 'administrator' group AuthN/AuthZ.
    Use a local Magpie test application.
    """

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.grp = get_constant('MAGPIE_ADMIN_GROUP')
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.app = utils.get_test_magpie_app()
        cls.json_headers = utils.get_headers(cls.app, {'Accept': JSON_TYPE, 'Content-Type': JSON_TYPE})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.check_requirements()

        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = utils.get_service_types_for_version(cls.version)[0]
        cls.test_service_name = utils.TestSetup.get_AnyServiceOfTestServiceType(cls)['service_name']

        cls.test_service_parent_resource_type = 'api'
        cls.test_service_parent_resource_name = 'magpie-unittest-ui-tree-parent'
        cls.test_service_child_resource_type = 'route'
        cls.test_service_child_resource_name = 'magpie-unittest-ui-tree-child'


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieUI_NoAuth_Remote(ti.Interface_MagpieUI_NoAuth, unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.json_headers = utils.get_headers(cls.url, {'Accept': JSON_TYPE, 'Content-Type': JSON_TYPE})
        cls.cookies = None
        cls.usr = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = 'wps'
        cls.test_service_name = 'flyingpigeon'


@runner.MAGPIE_TEST_UI
@runner.MAGPIE_TEST_REMOTE
class TestCase_MagpieUI_AdminAuth_Remote(ti.Interface_MagpieUI_AdminAuth, unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.url = get_constant('MAGPIE_TEST_REMOTE_SERVER_URL')
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(get_constant('MAGPIE_ADMIN_GROUP'))
        cls.json_headers = utils.get_headers(cls.url, {'Accept': JSON_TYPE, 'Content-Type': JSON_TYPE})
        cls.check_requirements()
        cls.version = utils.TestSetup.get_Version(cls)
        cls.test_user = get_constant('MAGPIE_ANONYMOUS_USER')
        cls.test_group = get_constant('MAGPIE_ANONYMOUS_GROUP')
        cls.test_service_type = utils.get_service_types_for_version(cls.version)[0]
        cls.test_service_name = utils.TestSetup.get_AnyServiceOfTestServiceType(cls)['service_name']
