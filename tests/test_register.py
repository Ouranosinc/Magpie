#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_register
----------------------------------

Tests for `magpie.register` operations.
"""
from magpie.constants import get_constant
from tests import utils, runner
import unittest


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REMOTE
@runner.MAGPIE_TEST_REGISTER
class TestRegister(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.grp = get_constant('MAGPIE_ADMIN_GROUP')
        cls.usr = get_constant('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = get_constant('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.json_headers = utils.get_headers(cls.url, {'Accept': 'application/json',
                                                       'Content-Type': 'application/json'})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        # TODO: fix UI views so that they can be 'found' directly in the WebTest.TestApp
        # NOTE: localhost magpie has to be running for following login call to work
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd,
                                                                 use_ui_form_submit=True, version=cls.version)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)


    def test_register_providers(self):
        pass


    def test_register_permissions(self):
        pass
