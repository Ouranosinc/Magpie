#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest


test_modules = [
    'test_magpie_api',
    'test_magpie_ui',
]


def test_suite():
    suite = unittest.TestSuite()
    for t in test_modules:
        try:
            # If the module defines a suite() function, call it to get the suite.
            mod = __import__(t, globals(), locals(), ['suite'])
            suite_fn = getattr(mod, 'suite')
            suite.addTest(suite_fn())
        except (ImportError, AttributeError):
            # else, just load all the test cases from the module.
            suite.addTest(unittest.defaultTestLoader.loadTestsFromName(t))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner().run(test_suite())
