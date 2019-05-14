from magpie import constants as c
import pytest


def test_get_constant_with_same_name():
    test_value = "test-constant"
    c.MAGPIE_CRON_LOG = test_value
    value = c.get_constant("MAGPIE_CRON_LOG")
    assert value == test_value


def test_get_constant_with_settings():
    settings = {
        "magpie.test_some_value": "some-value",
        "MAGPIE_TEST_ANOTHER": "another-value",
    }
    assert c.get_constant("MAGPIE_TEST_ANOTHER", settings) == settings["MAGPIE_TEST_ANOTHER"]
    assert c.get_constant("magpie.test_some_value", settings) == settings["magpie.test_some_value"]


def test_get_constant_alternative_name():
    settings = {"magpie.test_some_value": "some-value"}
    assert c.get_constant("MAGPIE_TEST_SOME_VALUE", settings) == settings["magpie.test_some_value"]


def test_get_constant_raise_missing_when_requested():
    with pytest.raises(LookupError):
        c.get_constant("MAGPIE_DOESNT_EXIST", raise_missing=True)

    try:
        value = c.get_constant("MAGPIE_DOESNT_EXIST", raise_missing=False)
        assert value is None
    except LookupError:
        pytest.fail(msg="Should not have raised although constant is missing.")


def test_get_constant_raise_not_set_when_requested():
    settings = {"magpie.not_set_but_exists": None}
    with pytest.raises(ValueError):
        c.get_constant("MAGPIE_NOT_SET_BUT_EXISTS", settings, raise_not_set=True)
    with pytest.raises(ValueError):
        c.get_constant("magpie.not_set_but_exists", settings, raise_not_set=True)

    try:
        value = c.get_constant("MAGPIE_NOT_SET_BUT_EXISTS", settings, raise_not_set=False)
        assert value is None
    except LookupError:
        pytest.fail(msg="Should not have raised although constant is not set.")
    try:
        value = c.get_constant("magpie.not_set_but_exists", settings, raise_not_set=False)
        assert value is None
    except LookupError:
        pytest.fail(msg="Should not have raised although constant is not set.")
