from typing import TYPE_CHECKING

from magpie.utils import ExtendedEnum

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Iterable, List, Optional

    from magpie.typedefs import AnyPermissionType, Str


class Permission(ExtendedEnum):
    """
    Applicable :term:`Permission` values under certain :term:`Service` and :term:`Resource`.
    """
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
    Converts any permission representation to the :class:`Permission` enum.

    If the permission cannot be matched to one of the enum's value, ``None`` is returned instead.
    """
    perm = Permission.get(permission)
    if perm is not None:
        return perm
    return Permission.get(getattr(permission, "perm_name", None) or permission)


def format_permissions(permissions):
    # type: (Iterable[AnyPermissionType]) -> List[Str]
    """
    Obtains the formatted permission representation after validation that it is a member of :class:`Permission` enum.

    The returned list is sorted alphabetically and cleaned of any duplicate entries.
    """
    perms = []
    for perm in permissions:
        p_enum = convert_permission(perm)
        if p_enum:
            perms.append(p_enum)
    return list(sorted({perm.value for perm in perms}))  # remove any duplicates entries
