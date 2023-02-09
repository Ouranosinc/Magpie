from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Tuple, Union

try:
    from packaging.version import InvalidVersion, Version as BaseVersion  # pylint: disable=unused-import

    class LooseVersion(BaseVersion):
        @property
        def version(self):
            # type: () -> Tuple[Union[int, str], ...]
            parts = [part for part in self._version[1:] if part is not None]
            parts = tuple(part_group for part in parts for part_group in part)
            return parts

        @property
        def patch(self):
            return self.micro

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
