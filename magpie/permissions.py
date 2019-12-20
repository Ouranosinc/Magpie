from magpie.utils import ExtendedEnumMeta
from six import with_metaclass
from enum import Enum
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.typedefs import Iterable, List, Optional, Str, AnyPermissionType  # noqa: F401


class Permission(with_metaclass(ExtendedEnumMeta, Enum)):
    # file/dir permissions
    READ = u"read"
    READ_MATCH = u"read-match"
    WRITE = u"write"
    WRITE_MATCH = u"write-match"
    ACCESS = u"access"
    # WPS permissions
    GET_CAPABILITIES = u"getcapabilities"
    GET_MAP = u"getmap"
    GET_FEATURE_INFO = u"getfeatureinfo"
    GET_LEGEND_GRAPHIC = u"getlegendgraphic"
    GET_METADATA = u"getmetadata"
    GET_FEATURE = u"getfeature"
    DESCRIBE_FEATURE_TYPE = u"describefeaturetype"
    DESCRIBE_PROCESS = u"describeprocess"
    EXECUTE = u"execute"
    LOCK_FEATURE = u"lockfeature"
    TRANSACTION = u"transaction"


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
