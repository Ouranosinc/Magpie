#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_security
----------------------------------

Tests for the security operations.
"""
import copy
import unittest

from magpie.security import mask_credentials
from tests import runner, utils


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_SECURITY
class TestSecurity(unittest.TestCase):
    """
    Validate operations of :mod:`magpie.security`.
    """

    def test_mask_credentials(self):
        body = {
            # regular request information shouldn't be modified
            "code": 400,
            "detail": "Some error with potential password leak.",
            "type": "application/json",
            "path": "/users/random-test-user",
            "url": "http://localhost:2001/magpie/users/random-test-user",
            "method": "PATCH",
            # flagged password matches should be redacted
            "password": "1234",  # noqa  # nosec
            "param": {
                "password_list": ["a", "b", "c"],  # noqa  # nosec
                "conditions": {"not_in": False},
                "value": 4,
                "name": "password",  # noqa  # nosec
                "password": "abcd",  # noqa  # nosec
                "compare": "range(0, 12)",
                "very": {
                    "very": {
                        "deep": {
                            "passwords": ["x", "y", "z"],  # noqa  # nosec
                            "nested": [
                                {"password": "x", "else": "x"},  # noqa  # nosec
                                {"password": "y", "else": "y"},  # noqa  # nosec
                                {"password": "z", "else": "z"},  # noqa  # nosec
                            ]
                        }
                    }
                }
            }
        }
        redact = "[REDACTED]"
        expect = copy.deepcopy(body)
        expect["password"] = redact  # noqa  # nosec
        expect["param"]["password"] = redact  # noqa  # nosec
        expect["param"]["password_list"] = [redact, redact, redact]  # noqa  # nosec
        expect["param"]["very"]["very"]["deep"]["passwords"] = [redact, redact, redact]  # noqa  # nosec
        for item in expect["param"]["very"]["very"]["deep"]["nested"]:  # noqa
            item["password"] = redact  # noqa  # nosec

        masked = mask_credentials(body, redact=redact)
        utils.check_val_equal(masked, expect)
