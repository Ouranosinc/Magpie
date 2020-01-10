#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import unittest
import warnings

import sqlalchemy.exc as sa_exc

from tests.utils import RunOptionDecorator  # noqa: F401

# ensure that files under 'tests' dir can be found (since not installed)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def filter_test_files(root, filename):
    return os.path.isfile(os.path.join(root, filename)) and filename.startswith("test") and filename.endswith(".py")


_TEST_ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
_TEST_ROOT_NAME = os.path.split(_TEST_ROOT_PATH)[1]
_TEST_FILES = os.listdir(_TEST_ROOT_PATH)
_TEST_MODULES = [os.path.splitext(f)[0] for f in filter(lambda i: filter_test_files(_TEST_ROOT_PATH, i), _TEST_FILES)]


# run test options, correspond to known pytest markers
MAGPIE_TEST_DEFAULTS = RunOptionDecorator("MAGPIE_TEST_DEFAULTS")   # default users, providers and views
MAGPIE_TEST_REGISTER = RunOptionDecorator("MAGPIE_TEST_REGISTER")   # methods employed in 'register' module
MAGPIE_TEST_LOGIN = RunOptionDecorator("MAGPIE_TEST_LOGIN")
MAGPIE_TEST_SERVICES = RunOptionDecorator("MAGPIE_TEST_SERVICES")
MAGPIE_TEST_RESOURCES = RunOptionDecorator("MAGPIE_TEST_RESOURCES")
MAGPIE_TEST_GROUPS = RunOptionDecorator("MAGPIE_TEST_GROUPS")
MAGPIE_TEST_USERS = RunOptionDecorator("MAGPIE_TEST_USERS")
MAGPIE_TEST_STATUS = RunOptionDecorator("MAGPIE_TEST_STATUS")  # validate views found/displayed as per permissions
MAGPIE_TEST_REMOTE = RunOptionDecorator("MAGPIE_TEST_REMOTE")
MAGPIE_TEST_LOCAL = RunOptionDecorator("MAGPIE_TEST_LOCAL")
MAGPIE_TEST_API = RunOptionDecorator("MAGPIE_TEST_API")
MAGPIE_TEST_UI = RunOptionDecorator("MAGPIE_TEST_UI")
MAGPIE_TEST_UTILS = RunOptionDecorator("MAGPIE_TEST_UTILS")
MAGPIE_TEST_FUNCTIONAL = RunOptionDecorator("MAGPIE_TEST_FUNCTIONAL")   # operations sequence


def test_suite():
    suite = unittest.TestSuite()
    for test_mod in _TEST_MODULES:
        try:
            # If the module defines a suite() function, call it to get the suite.
            mod = __import__(test_mod, globals(), locals(), ["suite"])
            suite_fn = getattr(mod, "suite")
            suite.addTest(suite_fn())
        except (ImportError, AttributeError):
            try:
                # else, just load all the test cases from the module.
                suite.addTest(unittest.defaultTestLoader.loadTestsFromName(test_mod))
            except AttributeError:
                # if still not found, try discovery from root directory
                suite.addTest(unittest.defaultTestLoader.discover(_TEST_ROOT_PATH))
    return suite


def run_suite():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=sa_exc.SAWarning)
        unittest.TextTestRunner().run(test_suite())


if __name__ == "__main__":
    run_suite()
