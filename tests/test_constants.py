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
    except (LookupError, ValueError):
        pytest.fail(msg="Should not have raised although constant is missing.")


@runner.MAGPIE_TEST_UTILS
def test_get_constant_raise_not_set_when_requested():
    settings = {"magpie.exists_but_not_set": None}
    with pytest.raises(LookupError):
        c.get_constant("MAGPIE_EXISTS_BUT_NOT_SET", {}, raise_not_set=True)
    with pytest.raises(LookupError):
        c.get_constant("magpie.exists_but_not_set", {}, raise_not_set=True)
    with pytest.raises(ValueError):
        c.get_constant("MAGPIE_EXISTS_BUT_NOT_SET", settings, raise_not_set=True)
    with pytest.raises(ValueError):
        c.get_constant("magpie.exists_but_not_set", settings, raise_not_set=True)

    try:
        value = c.get_constant("MAGPIE_EXISTS_BUT_NOT_SET", settings, raise_not_set=False)
        assert value is None
        value = c.get_constant("MAGPIE_EXISTS_BUT_NOT_SET", settings, raise_not_set=False, default_value=123)
        assert value == 123
    except (LookupError, ValueError):
        pytest.fail(msg="Should not have raised although constant is not set.")
    try:
        value = c.get_constant("magpie.exists_but_not_set", settings, raise_not_set=False)
        assert value is None
        value = c.get_constant("magpie.exists_but_not_set", settings, raise_not_set=False, default_value=123)
        assert value == 123
    except (LookupError, ValueError):
        pytest.fail(msg="Should not have raised although setting is not set.")


@runner.MAGPIE_TEST_UTILS
def test_get_constant_raise_empty_when_requested():
    settings = {"magpie.exists_but_empty": ""}
    with pytest.raises(LookupError):
        c.get_constant("MAGPIE_EXISTS_BUT_EMPTY", {}, raise_not_set=True, empty_missing=True)
    with pytest.raises(LookupError):
        c.get_constant("magpie.exists_but_empty", {}, raise_not_set=True, empty_missing=True)
    with pytest.raises(ValueError):
        c.get_constant("MAGPIE_EXISTS_BUT_EMPTY", settings, raise_not_set=True, empty_missing=True)
    with pytest.raises(ValueError):
        c.get_constant("magpie.exists_but_empty", settings, raise_not_set=True, empty_missing=True)

    try:
        value = c.get_constant("MAGPIE_EXISTS_BUT_EMPTY", settings, raise_not_set=True, empty_missing=False)
        assert value == ""
        value = c.get_constant("magpie.exists_but_empty", settings, raise_not_set=True, empty_missing=False)
        assert value == ""
    except (LookupError, ValueError):
        pytest.fail(msg="Should not have raised although constant is empty if not requested explicitly.")

    try:
        value = c.get_constant("MAGPIE_EXISTS_BUT_EMPTY", settings, raise_not_set=False, empty_missing=True)
        assert value is None
        value = c.get_constant("MAGPIE_EXISTS_BUT_EMPTY", settings, raise_not_set=False, empty_missing=True,
                               default_value="something else")
        assert value == "something else"
        value = c.get_constant("MAGPIE_EXISTS_BUT_EMPTY", settings, raise_not_set=False, empty_missing=True,
                               default_value="")
        assert value == "", "Explicit empty default value should be allowed even when empty missing requested."
    except (LookupError, ValueError):
        pytest.fail(msg="Should not have raised although constant is empty.")
    try:
        value = c.get_constant("magpie.exists_but_empty", settings, raise_not_set=False, empty_missing=True)
        assert value is None
        value = c.get_constant("magpie.exists_but_empty", settings, raise_not_set=False, empty_missing=True,
                               default_value="something else")
        assert value == "something else"
        value = c.get_constant("magpie.exists_but_empty", settings, raise_not_set=False, empty_missing=True,
                               default_value="")
        assert value == "", "Explicit empty default value should be allowed even when empty missing requested."
    except (LookupError, ValueError):
        pytest.fail(msg="Should not have raised although setting is empty.")


@runner.MAGPIE_TEST_UTILS
def test_constant_prioritize_setting_before_env_when_specified():
    settings = {"magpie.some_existing_var": "FROM_SETTING"}
    override = {"MAGPIE_SOME_EXISTING_VAR": "FROM_ENV"}
    with mock.patch.dict("os.environ", override):
        var = c.get_constant("MAGPIE_SOME_EXISTING_VAR", settings)
        assert var == settings["magpie.some_existing_var"]
        var = c.get_constant("MAGPIE_SOME_EXISTING_VAR")
        assert var == override["MAGPIE_SOME_EXISTING_VAR"]


@runner.MAGPIE_TEST_UTILS
def test_constant_protected_no_override():
    for const_name in c.MAGPIE_CONSTANTS:
        with mock.patch.dict("os.environ", {const_name: "override-value"}):
            const = c.get_constant(const_name)
            assert const != "override-value"
