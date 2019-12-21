import mock
import pytest

from magpie import constants as c
from tests import runner


@runner.MAGPIE_TEST_UTILS
def test_get_constant_with_same_name():
    test_value = "test-constant"
    c.MAGPIE_CRON_LOG = test_value
    value = c.get_constant("MAGPIE_CRON_LOG")
    assert value == test_value


@runner.MAGPIE_TEST_UTILS
def test_get_constant_with_settings():
    settings = {
        "magpie.test_some_value": "some-value",
        "MAGPIE_TEST_ANOTHER": "another-value",
    }
    assert c.get_constant("MAGPIE_TEST_ANOTHER", settings) == settings["MAGPIE_TEST_ANOTHER"]
    assert c.get_constant("magpie.test_some_value", settings) == settings["magpie.test_some_value"]


@runner.MAGPIE_TEST_UTILS
def test_get_constant_alternative_name():
    settings = {"magpie.test_some_value": "some-value"}
    assert c.get_constant("MAGPIE_TEST_SOME_VALUE", settings) == settings["magpie.test_some_value"]


@runner.MAGPIE_TEST_UTILS
def test_get_constant_raise_missing_when_requested():
    with pytest.raises(LookupError):
        c.get_constant("MAGPIE_DOESNT_EXIST", raise_missing=True)

    try:
        value = c.get_constant("MAGPIE_DOESNT_EXIST", raise_missing=False)
        assert value is None
    except LookupError:
        pytest.fail(msg="Should not have raised although constant is missing.")


@runner.MAGPIE_TEST_UTILS
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


@runner.MAGPIE_TEST_UTILS
def test_constant_prioritize_setting_before_env_when_specified():
    settings = {"magpie.some_existing_var": "FROM_SETTING"}
    override = {"MAGPIE_SOME_EXISTING_VAR": "FROM_ENV"}
    with mock.patch.dict("os.environ", override):
        var = c.get_constant("MAGPIE_SOME_EXISTING_VAR", settings)
        assert var == settings["magpie.some_existing_var"]
        var = c.get_constant("MAGPIE_SOME_EXISTING_VAR")
        assert var == override["MAGPIE_SOME_EXISTING_VAR"]
