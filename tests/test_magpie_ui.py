#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_ui
----------------------------------

Tests for `magpie.ui` module.
"""

import unittest
import pytest
import pyramid.testing
import six
import yaml
from magpie import *
from magpie.services import service_type_dict
from magpie import magpie
from test_utils import *


@pytest.mark.offline
@pytest.mark.ui
class TestMagpieUI_NoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.json_headers = [('Content-Type', 'application/json')]

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    def test_Home_valid(self):
        resp = test_request(self.app, 'GET', '/', headers=self.json_headers)
        assert resp.status_code == 200
        assert resp.content_type == 'text/html'
        resp.mustcontain("Magpie Administration")


@pytest.mark.online
@pytest.mark.ui
class TestMagpieUI_NoAuthRemote(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        assert cls.url, "cannot test without a remote server URL"

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    def test_Home_valid(self):
        resp = test_request(self.url, 'GET', '/')
        assert resp.status_code == 200
        assert resp.headers['Content-Type'] == 'text/html; charset=UTF-8'
        assert "Magpie Administration" in resp.text
