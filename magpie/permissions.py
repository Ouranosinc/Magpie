from typing import TYPE_CHECKING

from magpie.utils import ExtendedEnum

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Collection, Dict, List, Optional, Union

    from magpie.typedefs import AnyPermissionType, PermissionObject, Str


class Permission(ExtendedEnum):
    """
    Applicable :term:`Permission` values under certain :term:`Service` and :term:`Resource`.
    """
    # file/dir permissions
    READ = "read"
    WRITE = "write"
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

    The :class:`Permission` is the name of the applicable permission on the :class:`magpie.models.Resource`.
    The :class:`Scope` defines how the :class:`Permission` should impact the resolution of the perceived
    :term:`Effective Permission over a :class:`magpie.models.Resource` tree hierarchy.
    Finally, the :class:`Access` defines how the :class:`Permission` access should be interpreted (granted or denied).

    On missing :class:`Access` or :class:`Scope` specifications, they default to :attr:`Access.ALLOW` and
    :attr:`Scope.RECURSIVE` to handle backward compatible naming convention of plain ``permission_name``.
    """
    __slots__ = ["_name", "_access", "_scope"]

    def __init__(self, permission, access=None, scope=None):
        # type: (Union[Permission, Str], Optional[Union[Access, Str]], Optional[Union[Scope, Str]]) -> None
        if not isinstance(permission, Permission):
            perm_set = PermissionSet.convert(permission)
            permission = perm_set.name
            access = perm_set.access if access is None else access
            scope = perm_set.scope if scope is None else scope
        self.name = permission
        self.access = access
        self.scope = scope

    def __eq__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, PermissionSet):
            other = PermissionSet.convert(other)
        return self.permission == other.permission and self.access == other.access and self.scope == other.scope

    def __ne__(self, other):
        # type: (Any) -> bool
        return not self.__eq__(other)

    def __lt__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, PermissionSet):
            other = PermissionSet(other)
        return str(self) < str(other)

    def __hash__(self):
        # type: () -> int
        return hash((self.permission, self.access, self.scope))

    def __str__(self):
        # type: () -> Str
        """
        Obtains the compound literal representation of the :class:`PermissionSet`.

        Employed for database storage supporting ``ziggurat`` format.
        """
        return "{}-{}-{}".format(self.permission.value, self.access.value, self.scope.value)

    def __repr__(self):
        # type: () -> Str
        """
        Obtains the visual representation of the :class:`PermissionSet`.
        """
        perm_repr_template = "PermissionSet(name={}, access={}, scope={})"
        return perm_repr_template.format(self.permission.value, self.access.value, self.scope.value)

    def json(self):
        # type: () -> PermissionObject
        """
        Obtains the JSON representation of this :class:`PermissionSet`.
        """
        return {"name": self.permission.value, "access": self.access.value, "scope": self.scope.value}

    @property
    def implicit_permission(self):
        # type: () -> Optional[Str]
        """
        Obtain the implicit string representation of the :class:`PermissionSet` as plain :class:`Permission` name.

        This representation is backward compatible with prior versions of `Magpie` where explicit representation of
        permission names in the database did not exist.

        If the contained modifiers of the :class:`PermissionSet` (notably the :attr:`Access.DENY`) result in a string
        representation that is *not possible* according to non existing permissions fpr older `Magpie` instances, the
        returned value will be ``None``.

        .. seealso::
            - :meth:`explicit_permission` for the new representation.
        """
        if self.access == Access.ALLOW:
            if self.scope == Scope.RECURSIVE:
                return self.name.value
            if self.scope == Scope.MATCH:
                return "{}-{}".format(self.name.value, Scope.MATCH.value)
        return None

    @property
    def explicit_permission(self):
        # type: () -> Str
        """
        Obtain the explicit string representation of the :class:`PermissionSet`.

        .. seealso::
            - :meth:`__str__` (default string value).
            - :meth:`implicit_permission` for the old representation.
        """
        return str(self)

    @property
    def name(self):
        # type: () -> Permission
        return self._name

    @name.setter
    def name(self, permission):
        # type: (Union[Permission, Str]) -> None
        self._name = Permission.get(permission)
        if self._name is None:
            raise TypeError("Invalid permission: {!s}".format(permission))

    permission = name  # synonym

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

    @classmethod
    def convert(cls, permission):
        # type: (AnyPermissionType) -> Optional[PermissionSet]
        """
        Converts any permission representation to the :class:`PermissionSet` with applicable enum members.

        Supports older :class:`Permission` representation such that implicit conversion of permission name
        without :attr:`access` and :attr:`scope` values are padded with defaults. Also, pre-defined partial or full
        definition from literal string representation are parsed to generate the :class:`PermissionSet` instance.

        :param permission: implicit or explicit permission name string, or any other known permission implementation
        :raises ValueError: when the permission name cannot be identified or parsed
        """
        if isinstance(permission, PermissionSet):
            return permission
        if isinstance(permission, dict):
            name = permission.get(
                "name", permission.get("permission_name", permission.get("permission", permission.get("perm_name")))
            )
            perm = Permission.get(name)
            if perm is None:
                raise ValueError("Unknown permission name could not be identified: {}".format(name))
            return PermissionSet(perm, Access.get(permission.get("access")), Scope.get("scope"))
        name = getattr(permission, "perm_name", None) or permission  # ziggurat permission or plain string
        perm = Permission.get(name)
        if perm is not None:
            # when matched, a plain string or Permission enum was directly passed, infer the rest
            return PermissionSet(perm, Access.ALLOW, Scope.RECURSIVE)
        # note: old '-match' variants are not entries within 'Permission' enum anymore, so they are not found above
        if "-" not in name:
            raise ValueError("Unknown permission name could not be parsed: {}".format(name))
        perm, modifier = name.rsplit("-", 1)
        scope = Scope.get(modifier)
        if "-" not in perm:  # either compound perm-name or perm-[access|scope] combination
            if scope is None:
                access = Access.get(modifier, Access.ALLOW)
                scope = Scope.RECURSIVE
            else:
                access = Access.ALLOW
        else:
            name, access = perm.split("-")
            access = Access.get(access)
            if access is not None:
                perm = name
        perm = Permission.get(perm)
        return PermissionSet(perm, access, scope)


def format_permissions(permissions):
    # type: (Collection[AnyPermissionType]) -> Dict[Str, Union[List[Str], PermissionObject]]
    """
    Obtains the formatted permission representations after validation that the name is a known member of
    :class:`Permission` enum, and optionally with modifiers as defined by :class:`PermissionSet`.

    The returned lists are sorted alphabetically by permission *name* and cleaned of any duplicate entries.

    .. note::
        Field ``permission_names`` provides both the *older* implicit permission names and the *newer* explicit name
        representation. For this reason, there will be semantically "duplicate" permissions in that list, but there
        will not be any literal string duplicates. Implicit names are immediately followed by their explicit name,
        unless implicit names do not apply for the given permission (e.g.: when :attr:`Access.DENY`).
        Only the detailed and explicit JSON representations are provided in the ``permissions`` list.
    """
    unique_perms = sorted({PermissionSet.convert(perm) for perm in permissions})  # remove any duplicates entries
    bw_perm_names = []      # to preserve insert order
    bw_perm_unique = set()  # for quick remove of duplicates
    for perm in unique_perms:
        implicit_perm = perm.implicit_permission
        explicit_perm = perm.explicit_permission
        if implicit_perm is not None and implicit_perm not in bw_perm_unique:
            bw_perm_names.append(implicit_perm)
            bw_perm_unique.add(implicit_perm)
        if explicit_perm not in bw_perm_names:
            bw_perm_names.append(explicit_perm)
            bw_perm_unique.add(explicit_perm)
    return {
        "permission_names": bw_perm_names,  # backward compatible + explicit names
        "permissions": [perm.json() for perm in unique_perms]  # explicit objects
    }
