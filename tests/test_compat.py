import pytest

from magpie.compat import LooseVersion
from tests import runner


@runner.MAGPIE_TEST_UTILS
@pytest.mark.parametrize("version", [
    (1, 2, 3),
    ("1", "2", "3"),
    "1.2.3",
])
def test_version_setter(version):
    ver = LooseVersion("0.1.2")
    ver.version = version
    ver_str = ".".join([str(v) for v in version]) if isinstance(version, tuple) else version
    assert str(ver) == ver_str
    assert ver.major == 1
    assert ver.minor == 2
    assert ver.patch == 3
