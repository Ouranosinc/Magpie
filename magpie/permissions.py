from enum import Enum
from typing import TYPE_CHECKING

from six import with_metaclass

from magpie.utils import ExtendedEnumMeta

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import Iterable, List, Optional, Str, AnyPermissionType  # noqa: F401


class Permission(with_metaclass(ExtendedEnumMeta, Enum)):
    # file/dir permissions
    READ = "read"
    READ_MATCH = "read-match"
    WRITE = "write"
    WRITE_MATCH = "write-match"
    ACCESS = "access"
    # WPS permissions
    GET_CAPABILITIES = "getcapabilities"
    GET_MAP = "getmap"
    GET_FEATURE_INFO = "getfeatureinfo"
    GET_LEGEND_GRAPHIC = "getlegendgraphic"
    GET_METADATA = "getmetadata"
    GET_FEATURE = "getfeature"
    DESCRIBE_FEATURE_TYPE = "describefeaturetype"
    DESCRIBE_PROCESS = "describeprocess"
    EXECUTE = "execute"
    LOCK_FEATURE = "lockfeature"
    TRANSACTION = "transaction"


def convert_permission(permission):
    # type: (AnyPermissionType) -> Optional[Permission]
    """
    Converts any permission representation to the ``Permission`` enum.

    If the permission cannot be matched to one of the enum's value, ``None`` is returned instead.
    """
    if permission in Permission:
        return permission
    return Permission.get(getattr(permission, "perm_name", None) or permission)


def format_permissions(permissions):
    # type: (Iterable[AnyPermissionType]) -> List[Str]
    """
    Obtains the formatted permission representation after validation that it is a member of ``Permission`` enum.

    The returned list is sorted alphabetically and cleaned of any duplicate entries.
    """
    perms = []
    for p in permissions:
        p_enum = convert_permission(p)
        if p_enum:
            perms.append(p_enum)
    return list(sorted(set([p.value for p in perms])))  # remove any duplicates entries
