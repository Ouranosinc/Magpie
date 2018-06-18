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


@pytest.mark.online
class TestMagpie(unittest.TestCase):

    def setUp(self):
        base_path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        config_uri = '{}/magpie/magpie.ini'.format(base_path)
        parser = ConfigParser.ConfigParser()
        parser.read([config_uri])
        self.json_headers = [('Content-Type', 'application/json')]
        self.settings = dict(parser.items('app:magpie_app'))
        self.magpie_url = self.settings['magpie.url']
        self.config = pyramid.testing.setUp(settings=self.settings)
        self.config.add_settings({'ziggurat_foundations.model_locations.User': 'magpie.models:User'})
        self.config.include('magpie')
        self.config.scan('magpie')
        self.app = TestApp(magpie.main({}, **self.config.registry.settings))

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
