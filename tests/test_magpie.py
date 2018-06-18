#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie
----------------------------------

Tests for `magpie` module.
"""

import unittest
import pytest
import os
import ConfigParser
import pyramid.testing
from webtest import TestApp
from magpie import magpie
MAGPIE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def config_setup_from_ini(config_ini_file_path, ini_main_section_name):
    parser = ConfigParser.ConfigParser()
    parser.read([config_ini_file_path])
    settings = dict(parser.items(ini_main_section_name))
    config = pyramid.testing.setUp(settings=settings)
    return config


@pytest.mark.online
class TestMagpie(unittest.TestCase):

    def setUp(self):
        # parse settings from ini file to pass them to the application
        magpie_ini = '{}/magpie/magpie.ini'.format(MAGPIE_DIR)
        self.config = config_setup_from_ini(magpie_ini, 'app:magpie_app')
        # required redefinition because root models' location is not the same from within this test file
        self.config.add_settings({'ziggurat_foundations.model_locations.User': 'magpie.models:User'})
        # scan dependencies
        self.config.include('magpie')
        self.config.scan('magpie')
        # create the test application
        self.app = TestApp(magpie.main({}, **self.config.registry.settings))
        self.json_headers = [('Content-Type', 'application/json')]

    def tearDown(self):
        pyramid.testing.tearDown()

    def test_Home_Success(self):
        resp = self.app.get('/', headers=self.json_headers)
        assert resp.status_int == 200
        assert resp.content_type == 'text/html'
        resp.mustcontain("Magpie Administration")

    def test_GetService_Success(self):
        resp = self.app.get('/version', headers=self.json_headers)
        assert resp.status_int == 200
        assert resp.content_type == 'application/json'
        assert resp.json['version'] == magpie.__meta__.__version__




if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
