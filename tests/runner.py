#!/usr/bin/env python
# -*- coding: utf-8 -*-
from magpie.common import str2bool
import sqlalchemy.exc as sa_exc
import unittest
import warnings
import os


test_root_path = os.path.abspath(os.path.dirname(__file__))
test_root_name = os.path.split(test_root_path)[1]
test_modules = [
    '{}.test_magpie_api'.format(test_root_name),
    '{}.test_magpie_ui'.format(test_root_name),
]

# run test options
MAGPIE_TEST_DEFAULTS = str2bool(os.getenv('MAGPIE_TEST_DEFAULTS', True))
MAGPIE_TEST_LOGIN = str2bool(os.getenv('MAGPIE_TEST_LOGIN', True))
MAGPIE_TEST_SERVICES = str2bool(os.getenv('MAGPIE_TEST_SERVICES', True))
MAGPIE_TEST_RESOURCES = str2bool(os.getenv('MAGPIE_TEST_RESOURCES', True))
MAGPIE_TEST_GROUPS = str2bool(os.getenv('MAGPIE_TEST_GROUPS', True))
MAGPIE_TEST_USERS = str2bool(os.getenv('MAGPIE_TEST_USERS', True))
MAGPIE_TEST_STATUS = str2bool(os.getenv('MAGPIE_TEST_STATUS', True))
MAGPIE_TEST_REMOTE = str2bool(os.getenv('MAGPIE_TEST_REMOTE', True))
MAGPIE_TEST_LOCAL = str2bool(os.getenv('MAGPIE_TEST_LOCAL', True))
MAGPIE_TEST_API = str2bool(os.getenv('MAGPIE_TEST_API', True))
MAGPIE_TEST_UI = str2bool(os.getenv('MAGPIE_TEST_UI', True))


def test_suite():
    suite = unittest.TestSuite()
    for t in test_modules:
        try:
            # If the module defines a suite() function, call it to get the suite.
            mod = __import__(t, globals(), locals(), ['suite'])
            suite_fn = getattr(mod, 'suite')
            suite.addTest(suite_fn())
        except (ImportError, AttributeError):
            try:
                # else, just load all the test cases from the module.
                suite.addTest(unittest.defaultTestLoader.loadTestsFromName(t))
            except AttributeError:
                # if still not found, try discovery from root directory
                #tests = unittest.defaultTestLoader.loadTestsFromModule(t)
                #suite.addTests(tests)
                suite.addTest(unittest.defaultTestLoader.discover(test_root_path))
    return suite


def run_suite():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=sa_exc.SAWarning)
        unittest.TextTestRunner().run(test_suite())


if __name__ == '__main__':
    run_suite()
