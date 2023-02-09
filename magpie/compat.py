import inspect
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Tuple, Union

try:
    from packaging.version import InvalidVersion  # pylint: disable=unused-import
    from packaging.version import Version as BaseVersion  # pylint: disable=unused-import
    from packaging.version import _Version as TupleVersion  # pylint: disable=W0212,protected-access

    class LooseVersion(BaseVersion):
        @property
        def version(self):
            # type: () -> Tuple[Union[int, str], ...]
            parts = [part for part in self._version[1:] if part is not None]
            parts = tuple(part_group for part in parts for part_group in part)
            return parts

        @version.setter
        def version(self, version):
            # type: (Union[Tuple[Union[int, str], ...], str, TupleVersion]) -> None
            if isinstance(version, tuple) and all(isinstance(part, int) for part in version):
                fields = {field: None for field in TupleVersion._fields if field not in ["epoch", "release"]}
                self._version = TupleVersion(epoch=0, release=version, **fields)
            elif isinstance(version, str):
                self._version = LooseVersion(version)._version  # pylint: disable=W0212,protected-access
            elif isinstance(version, TupleVersion):
                self._version = version
            else:
                cls = version if inspect.isclass(version) else type(version)
                name = ".".join([version.__module__, cls.__name__])
                raise TypeError("Unknown parsing method for version type: {}".format(name))

        @property
        def patch(self):
            return self.micro

        def _cmp(self, other):
            # type: (Union[LooseVersion, str]) -> int
            if isinstance(other, str):
                other = LooseVersion(other)
            elif not isinstance(other, LooseVersion):
                return NotImplemented
            if self.version == other.version:
                return 0
            if self.version < other.version:
                return -1
            if self.version > other.version:
                return 1

except ImportError:  # pragma: no cover  # for backward compatibility
    from distutils.version import LooseVersion as BaseVersion  # pylint: disable=deprecated-module

    InvalidVersion = ValueError

    class LooseVersion(BaseVersion):
        @property
        def major(self):
            # type: () -> int
            num = self.version[0:1]
            return int(num[0]) if num else None

        @property
        def minor(self):
            # type: () -> int
            num = self.version[1:2]
            return int(num[0]) if num else None

        @property
        def patch(self):
            # type: () -> int
            num = self.version[2:3]
            return int(num[0]) if num else None

        @property
        def micro(self):
            # type: () -> int
            return self.patch
