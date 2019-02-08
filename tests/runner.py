#!/usr/bin/env python
# -*- coding: utf-8 -*-
from utils import RunOptionDecorator
import sqlalchemy.exc as sa_exc
import unittest
import warnings
import os
import sys

# ensure that files under 'tests' dir can be found (since not installed)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def filter_test_files(root, filename):
    return os.path.isfile(os.path.join(root, filename)) and filename.startswith('test') and filename.endswith('.py')


test_root_path = os.path.abspath(os.path.dirname(__file__))
test_root_name = os.path.split(test_root_path)[1]
test_files = os.listdir(test_root_path)
test_modules = [os.path.splitext(f)[0] for f in filter(lambda i: filter_test_files(test_root_path, i), test_files)]


# run test options
MAGPIE_TEST_DEFAULTS = RunOptionDecorator('MAGPIE_TEST_DEFAULTS')   # default users, providers and views
MAGPIE_TEST_REGISTER = RunOptionDecorator('MAGPIE_TEST_REGISTER')   # methods employed in 'register' module
MAGPIE_TEST_LOGIN = RunOptionDecorator('MAGPIE_TEST_LOGIN')
MAGPIE_TEST_SERVICES = RunOptionDecorator('MAGPIE_TEST_SERVICES')
MAGPIE_TEST_RESOURCES = RunOptionDecorator('MAGPIE_TEST_RESOURCES')
MAGPIE_TEST_GROUPS = RunOptionDecorator('MAGPIE_TEST_GROUPS')
MAGPIE_TEST_USERS = RunOptionDecorator('MAGPIE_TEST_USERS')
MAGPIE_TEST_STATUS = RunOptionDecorator('MAGPIE_TEST_STATUS')  # validate views found/displayed as per permissions
MAGPIE_TEST_REMOTE = RunOptionDecorator('MAGPIE_TEST_REMOTE')
MAGPIE_TEST_LOCAL = RunOptionDecorator('MAGPIE_TEST_LOCAL')
MAGPIE_TEST_API = RunOptionDecorator('MAGPIE_TEST_API')
MAGPIE_TEST_UI = RunOptionDecorator('MAGPIE_TEST_UI')
MAGPIE_TEST_UTILS = RunOptionDecorator('MAGPIE_TEST_UTILS')


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
