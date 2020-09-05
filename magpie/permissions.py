from typing import TYPE_CHECKING

from magpie.utils import ExtendedEnum

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Collection, Dict, List, Optional, Union

    from magpie.typedefs import AnyPermissionType, PermissionObject, Str


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


class Access(ExtendedEnum):
    """
    Applicable access modifier of :term:`Permission` values.
    """
    ALLOW = "allow"
    DENY = "deny"


class Scope(ExtendedEnum):
    """
    Applicable access modifier of :term:`Permission` values.
    """
    MATCH = "match"
    RECURSIVE = "recursive"


class PermissionSet(object):
    """
    Explicit definition of a :class:`Permission` with applicable :class:`Access` and :class:`Scope` to resolve it.

    On missing :class:`Access` or :class:`Scope` specifications, defaults to :attr:`Access.ALLOW` and
    :attr:`Scope.RECURSIVE` to handled backward compatible naming convention of plain ``permission_name``.
    """
    _perm = None    # type: Permission
    _access = None  # type: Access
    _scope = None   # type: Scope

    def __init__(self, permission, access, scope):
        # type: (Union[Permission, Str], Optional[Union[Access, Str]], Optional[Union[Scope, Str]]) -> None
        self.permission = permission
        self.access = access
        self.scope = scope

    @property
    def permission(self):
        # type: () -> Permission
        return self._perm

    @permission.setter
    def permission(self, permission):
        # type: (Union[Permission, Str]) -> None
        self._perm = Permission.get(permission)
        if self._perm is None:
            raise TypeError("Invalid permission: {!s}".format(permission))

    @property
    def access(self):
        # type: () -> Access
        return self._access

    @access.setter
    def access(self, access):
        # type: (Optional[Union[Access, Str]]) -> None
        self._access = Access.get(access, default=Access.ALLOW)

    @property
    def scope(self):
        # type: () -> Scope
        return self._scope

    @scope.setter
    def scope(self, scope):
        # type: (Optional[Union[Scope, Str]]) -> None
        self._scope = Scope.get(scope, default=Scope.RECURSIVE)

    def __str__(self):
        """
        Obtains the compound representation of the permission set for database storage supporting ``ziggurat`` format.
        """
        return "{}-{}-{}".format(self._perm.value, self._access.value, self._scope.value)

    @classmethod
    def convert(cls, permission):
        # type: (AnyPermissionType) -> Optional[PermissionSet]
        """
        Converts any permission representation to the :class:`PermissionSet` with applicable enum members.

        If the permission cannot be matched to one of the enum's value, ``None`` is returned instead.
        Furthermore, supports older :class:`Permission` representation such that implicit conversion of permission name
        without :attr:`access` and :attr:`scope` values are padded.
        """
        if isinstance(permission, dict):
            name = permission.get(
                "name", permission.get("permission_name", permission.get("permission", permission["perm_name"]))
            )
            return PermissionSet(Permission.get(name), Access.get(permission.get("access")), Scope.get("scope"))
        perm = Permission.get(permission)
        if perm is not None:
            return PermissionSet(perm, Access.ALLOW, Scope.RECURSIVE)
        perm = Permission.get(getattr(permission, "perm_name", None) or permission)

    def json(self):
        # type: () -> PermissionObject
        """
        Obtains the JSON representation of this :class:`PermissionSet`.
        """
        return {"name": self._perm.value, "access": self._access.value, "scope": self._scope.value}


def format_permissions(permissions):
    # type: (Collection[AnyPermissionType]) -> Dict[Str, Union[List[Str], PermissionObject]]
    """
    Obtains the formatted permission representation after validation that it is a member of :class:`Permission` enum.

    The returned list is sorted alphabetically and cleaned of any duplicate entries.
    """
    perms = []
    for perm in permissions:
        p_enum = convert_permission(perm)
        if p_enum:
            perms.append(p_enum)
    return list(sorted(set([p.value for p in perms])))  # remove any duplicates entries

"permission_names": list() if perms is None else format_permissions(perms)
