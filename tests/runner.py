#!/usr/bin/env python
# -*- coding: utf-8 -*-
from magpie.common import str2bool
from magpie.constants import get_constant
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


def default_run(option):
    option_value = str2bool(get_constant(option, raise_missing=False, raise_not_set=False))
    return True if option_value is None else option_value


# run test options
MAGPIE_TEST_DEFAULTS = default_run('MAGPIE_TEST_DEFAULTS')  # default users, providers and views
MAGPIE_TEST_LOGIN = default_run('MAGPIE_TEST_LOGIN')
MAGPIE_TEST_SERVICES = default_run('MAGPIE_TEST_SERVICES')
MAGPIE_TEST_RESOURCES = default_run('MAGPIE_TEST_RESOURCES')
MAGPIE_TEST_GROUPS = default_run('MAGPIE_TEST_GROUPS')
MAGPIE_TEST_USERS = default_run('MAGPIE_TEST_USERS')
MAGPIE_TEST_STATUS = default_run('MAGPIE_TEST_STATUS')  # validate views found and displayed correctly as per permission
MAGPIE_TEST_REMOTE = default_run('MAGPIE_TEST_REMOTE')
MAGPIE_TEST_LOCAL = default_run('MAGPIE_TEST_LOCAL')
MAGPIE_TEST_API = default_run('MAGPIE_TEST_API')
MAGPIE_TEST_UI = default_run('MAGPIE_TEST_UI')


def MAGPIE_TEST_DISABLED_MESSAGE(option):
    return "Skip{}tests requested.".format(" '{}' ".format(option) if option else '')


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
