import functools
import itertools
from typing import TYPE_CHECKING

import six
from pyramid.security import Everyone

from magpie.utils import ExtendedEnum

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Collection, Dict, List, Optional, Union

    from magpie import models
    from magpie.typedefs import AccessControlEntryType, AnyPermissionType, PermissionObject, Str


class Permission(ExtendedEnum):
    """
    Applicable :term:`Permission` values (names) under certain :term:`Service` and :term:`Resource`.
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


class PermissionType(ExtendedEnum):
    """
    Applicable types of :term:`Permission` according to context.
    """
    ACCESS = "access"           # role based, accessible views
    ALLOWED = "allowed"         # available for given service / resource (under service-type)
    APPLIED = "applied"         # defined (user|group, service|resource, permission)
    DIRECT = "direct"           # applied, only for user situation
    INHERITED = "inherited"     # applied, combined for user+group, relative to user member
    EFFECTIVE = "effective"     # resolved user+group for resource hierarchy, with access and scope
    OWNED = "owned"             # user/group explicitly owns the permission


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


@functools.total_ordering
class PermissionSet(object):
    """
    Explicit definition of a :class:`Permission` with applicable :class:`Access` and :class:`Scope` to resolve it.

    The :class:`Permission` is the *name* of the applicable permission on the :class:`magpie.models.Resource`.
    The :class:`Scope` defines how the :class:`Permission` should impact the resolution of the perceived
    :term:`Effective Permissions` over a :class:`magpie.models.Resource` tree hierarchy.
    The :class:`Access` defines how the :class:`Permission` access should be interpreted (granted or denied).

    Optionally, a :class:`PermissionType` can be provided to specifically indicate which kind of permission this set
    represents. This type is only for informative purposes, and is not saved to database nor displayed by the explicit
    string representation. It is returned within JSON representation and can be employed by
    :term:`Effective Permissions` resolution to be more verbose about returned results.

    On missing :class:`Access` or :class:`Scope` specifications, they default to :attr:`Access.ALLOW` and
    :attr:`Scope.RECURSIVE` to handle backward compatible naming convention of plain ``permission_name``.
    """
    __slots__ = ["_name", "_access", "_scope", "_type"]

    def __init__(self,
                 permission,    # type: AnyPermissionType
                 access=None,   # type: Optional[Union[Access, Str]]
                 scope=None,    # type: Optional[Union[Scope, Str]]
                 typ=None,      # type: Optional[PermissionType]
                 ):             # type: (...) -> None
        """
        Initializes the permission definition, possibly using required conversion from other implementations.

        :param permission: Name of the permission, or any other implementation from which the name can be inferred.
        :param access: Effective behaviour of the permissions. Generally, grant or deny the specified permission.
        :param scope: Scope for which the permission affects hierarchical resources. Important for effective resolution.
        :param typ: Type of permission being represented. Informative only, does not impact behavior if omitted.

        .. seealso::
            :meth:`PermissionSet.convert`
        """
        if not isinstance(permission, Permission):
            perm_set = PermissionSet.convert(permission)
            permission = perm_set.name
            access = perm_set.access if access is None else access
            scope = perm_set.scope if scope is None else scope
            typ = perm_set.type if perm_set.type is not None else typ
        self.name = permission
        self.access = access
        self.scope = scope
        self.type = typ

    def __eq__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, PermissionSet):
            other = PermissionSet.convert(other)
        return self.json() == other.json()

    def __ne__(self, other):
        # type: (Any) -> bool
        return not self.__eq__(other)

    def __lt__(self, other):
        # type: (Any) -> bool
        """
        Sort by permission name, followed by *more permissive access* and *more generic scope*.

        Using this sorting methodology, similar permissions by name are grouped together first, and permissions of same
        name with modifiers are then ordered from ``allow-recursive`` to ``deny-match``, the first having less priority
        in the :term:`Effective Permissions` resolution than the later. Respecting :attr:`Access.DENY` is more important
        than :attr:`Access.ALLOW` (to protect the :term:`Resource`), and :attr:`Scope.MATCH` is *closer* to the actual
        :term:`Resource` than :attr:`Scope.RECURSIVE` permission received from a *farther* parent in the hierarchy.
        """
        if not isinstance(other, PermissionSet):
            other = PermissionSet(other)
        if self.name != other.name:
            return self.name.value < other.name.value
        if self.access != other.access:
            return self.access == Access.ALLOW
        if self.scope != other.scope:
            return self.scope == Scope.RECURSIVE
        return False

    def __hash__(self):
        # type: () -> int
        return hash((self.name, self.access, self.scope))

    def __str__(self):
        # type: () -> Str
        """
        Obtains the compound literal representation of the :class:`PermissionSet`.

        Employed for database storage supporting ``ziggurat`` format.
        """
        return "{}-{}-{}".format(self.name.value, self.access.value, self.scope.value)

    def __repr__(self):
        # type: () -> Str
        """
        Obtains the visual representation of the :class:`PermissionSet`.
        """
        perm_repr_template = "PermissionSet(name={}, access={}, scope={}, type={})"
        perm_type = self.type.value if self.type is not None else None
        return perm_repr_template.format(self.name.value, self.access.value, self.scope.value, perm_type)

    def like(self, other):
        """
        Evaluates if one permission is *similar* to another permission definition regardless of *modifiers*.

        This is different than ``==`` operator which will evaluate *exactly* equal permission definitions.
        """
        if not isinstance(other, PermissionSet):
            other = PermissionSet(other)
        return self.name == other.name

    def json(self):
        # type: () -> PermissionObject
        """
        Obtains the JSON representation of this :class:`PermissionSet`.
        """
        return {
            "name": self.name.value,
            "access": self.access.value,
            "scope": self.scope.value,
            "type": self.type.value if self.type is not None else None,
        }

    def ace(self, user_or_group):
        # type: (Optional[Union[models.User, models.Group]]) -> AccessControlEntryType
        """
        Converts the :class:`PermissionSet` into an :term:`ACE` that :mod:`pyramid` can understand.
        """
        outcome = self.access.value.capitalize()  # pyramid: Access/Deny
        if user_or_group is None:
            target = Everyone
        elif self.type == PermissionType.INHERITED:
            target = "group:{}".format(user_or_group.id)
        else:  # both DIRECT and EFFECTIVE (effective is pre-computed with inherited permissions for the user)
            target = user_or_group.id
        return outcome, target, self.name.value

    @property
    def implicit_permission(self):
        # type: () -> Optional[Str]
        """
        Obtain the implicit string representation of the :class:`PermissionSet` as plain :class:`Permission` name.

        This representation is backward compatible with prior versions of `Magpie` where explicit representation of
        permission names in the database did not exist.

        If the contained modifiers of the :class:`PermissionSet` (notably the :attr:`Access.DENY`) result in a string
        representation that is *not possible* according to non existing permissions for older `Magpie` instances, the
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

        This format is always guaranteed to be completely defined contrary to :meth:`implicit_permission`.

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

    permission = name  # synonym to match init parameters

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

    @property
    def type(self):
        # type: () -> Optional[PermissionType]
        return self._type

    @type.setter
    def type(self, typ):
        self._type = PermissionType.get(typ)

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

        # JSON representation
        if isinstance(permission, dict):
            name = permission.get(
                "name", permission.get("permission_name", permission.get("permission", permission.get("perm_name")))
            )
            perm = Permission.get(name)
            if perm is None:
                raise ValueError("Unknown permission name could not be identified: {}".format(name))
            access = Access.get(permission.get("access"))
            scope = Scope.get(permission.get("scope"))
            typ = PermissionType.get(permission.get("type"))
            return PermissionSet(perm, access, scope, typ)

        # pyramid ACE representation
        if isinstance(permission, tuple) and len(permission) == 3:
            perm_type = PermissionType.INHERITED if "group" in str(permission[1]) else PermissionType.DIRECT
            perm_name = permission[2]
            # if permission name represents explicit definition, use it directly and drop Allow/Deny from ACE
            # otherwise, use the provided access
            access = None
            if isinstance(perm_name, six.string_types) and len(perm_name.split("-")) != 3:
                access = Access.get(permission[0].lower())
            return PermissionSet(perm_name, access=access, scope=None, typ=perm_type)

        # ziggurat PermissionTuple or plain string representation
        name = getattr(permission, "perm_name", None) or permission
        perm = Permission.get(name)  # old '-match' variants are not in enum anymore, so they are not found here
        perm_type = getattr(permission, "type", None)  # ziggurat PermissionTuple
        if perm_type == "user":
            perm_type = PermissionType.DIRECT
        elif perm_type == "group":
            perm_type = PermissionType.INHERITED
        if perm is not None:
            # when matched, either plain permission-name string or Permission enum, or AllPermissionList was passed
            # infer the rest of the parameters
            return PermissionSet(perm, Access.ALLOW, Scope.RECURSIVE, perm_type)

        # only permission-name at this point (with mandatory '-') as without it would be found by above 'Permission.get'
        if not isinstance(name, six.string_types):
            raise TypeError("Unknown permission object cannot be converted: {!r}".format(name))
        if "-" not in name:
            raise ValueError("Unknown permission name could not be parsed: {}".format(name))

        # plain string representation, either implicit or explicit
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
        return PermissionSet(perm, access, scope, perm_type)


def format_permissions(permissions,             # type: Optional[Collection[AnyPermissionType]]
                       permission_type=None,    # type: Optional[PermissionType]
                       ):                       # type: (...) -> Dict[Str, Union[List[Str], PermissionObject, Str]]
    """
    Obtains the formatted permission representations after validation that each of their name is a known member of
    :class:`Permission` enum, and optionally with modifiers as defined by :class:`PermissionSet`.

    The returned lists are sorted alphabetically by permission *name* and cleaned of any duplicate entries.
    If no or empty :paramref:`permissions` is provided, empty lists are returned.

    .. note::
        Field ``permission_names`` provides both the *older* implicit permission names and the *newer* explicit name
        representation. For this reason, there will be semantically "duplicate" permissions in that list, but there
        will not be any literal string duplicates. Implicit names are immediately followed by their explicit name,
        unless implicit names do not apply for the given permission (e.g.: when :attr:`Access.DENY`).
        Only the detailed and explicit JSON representations are provided in the ``permissions`` list.

    When :paramref:`permission_type` is equal to :attr:`PermissionType.ALLOWED`, the collection of every applicable
    :class:`PermissionSet` is automatically generated by expanding all combinations of :class:`Access` and
    :class:`Scope` with every provided :class:`Permission` name in :paramref:`permissions`. This allows more concise
    definition of allowed permissions under :class:`magpie.services.Services` and their children :term:`Resources` by
    only defining :class:`Permission` names without manually listing all variations of :class:`PermissionSet`.

    For other :paramref:`permission_type` values, which represent :term:`Applied Permissions` only specifically
    provided :paramref:`permissions` are returned, to effectively return the collection of *active* permissions.

    :param permissions: multiple permissions of any implementation and type, to be rendered both as names and JSON.
    :param permission_type: indication of the represented permissions to be formatted, for informative indication.
    :returns: JSON with the permissions listed as implicit+explicit names, as permission set objects, and their type.
    """
    json_perms = []
    bw_perm_names = []  # to preserve insert order
    if permission_type is None:
        permission_type = PermissionType.ALLOWED
    if permissions:
        bw_perm_unique = set()  # for quick remove of duplicates
        unique_perms = sorted({PermissionSet(perm, typ=permission_type) for perm in permissions})
        if permission_type == PermissionType.ALLOWED:
            unique_names = {perm.name for perm in unique_perms}  # trim out any extra variations, then build full list
            unique_perms = sorted([PermissionSet(name, access, scope, PermissionType.ALLOWED)
                                   for name, access, scope in itertools.product(unique_names, Access, Scope)])
        for perm in unique_perms:
            implicit_perm = perm.implicit_permission
            explicit_perm = perm.explicit_permission
            if implicit_perm is not None and implicit_perm not in bw_perm_unique:
                bw_perm_names.append(implicit_perm)
                bw_perm_unique.add(implicit_perm)
            if explicit_perm not in bw_perm_names:
                bw_perm_names.append(explicit_perm)
                bw_perm_unique.add(explicit_perm)
        json_perms = [perm.json() for perm in unique_perms]
    for perm in json_perms:
        perm["type"] = permission_type.value
    return {
        "permission_names": bw_perm_names,  # backward compatible + explicit names
        "permissions": json_perms           # explicit objects with types
    }
