#!/usr/bin/env python
# -*- coding: utf-8 -*-
from utils import Run
import sqlalchemy.exc as sa_exc
import unittest
import warnings
import os


def filter_test_files(root, filename):
    return os.path.isfile(os.path.join(root, filename)) and filename.startswith('test') and filename.endswith('.py')


test_root_path = os.path.abspath(os.path.dirname(__file__))
test_root_name = os.path.split(test_root_path)[1]
test_files = os.listdir(test_root_path)
test_modules = [os.path.splitext(f)[0] for f in filter(lambda i: filter_test_files(test_root_path, i), test_files)]


# run test options
MAGPIE_TEST_DEFAULTS = RunOption('MAGPIE_TEST_DEFAULTS')  # default users, providers and views
MAGPIE_TEST_REGISTER = RunOption('MAGPIE_TEST_REGISTER')
MAGPIE_TEST_LOGIN = RunOption('MAGPIE_TEST_LOGIN')
MAGPIE_TEST_SERVICES = RunOption('MAGPIE_TEST_SERVICES')
MAGPIE_TEST_RESOURCES = RunOption('MAGPIE_TEST_RESOURCES')
MAGPIE_TEST_GROUPS = RunOption('MAGPIE_TEST_GROUPS')
MAGPIE_TEST_USERS = RunOption('MAGPIE_TEST_USERS')
MAGPIE_TEST_STATUS = RunOption('MAGPIE_TEST_STATUS')  # validate views found and displayed correctly as per permission
MAGPIE_TEST_REMOTE = RunOption('MAGPIE_TEST_REMOTE')
MAGPIE_TEST_LOCAL = RunOption('MAGPIE_TEST_LOCAL')
MAGPIE_TEST_API = RunOption('MAGPIE_TEST_API')
MAGPIE_TEST_UI = RunOption('MAGPIE_TEST_UI')


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
                # tests = unittest.defaultTestLoader.loadTestsFromModule(t)
                # suite.addTests(tests)
                suite.addTest(unittest.defaultTestLoader.discover(test_root_path))
    return suite


def run_suite():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=sa_exc.SAWarning)
        # noinspection PyUnresolvedReferences
        unittest.TextTestRunner().run(test_suite())


if __name__ == '__main__':
    run_suite()
