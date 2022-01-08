import functools
import itertools
from typing import TYPE_CHECKING

import six
from pyramid.security import Everyone
from ziggurat_foundations.permissions import PermissionTuple  # noqa

from magpie.utils import ExtendedEnum

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Collection, Dict, List, Optional, Union

    from magpie import models
    from magpie.typedefs import (
        AccessControlEntryType,
        AnyPermissionType,
        GroupPriority,
        JSON,
        PermissionDict,
        ResolvablePermissionType,
        Str
    )

# values employed for special cases of 'PermissionSet.reason' during permission resolution
PERMISSION_REASON_DEFAULT = "no-permission"
PERMISSION_REASON_MULTIPLE = "multiple"
PERMISSION_REASON_ADMIN = "administrator"


class Permission(ExtendedEnum):
    """
    Applicable :term:`Permission` values (names) under certain :term:`Service` and :term:`Resource`.
    """
    # file/dir permissions
    READ = "read"
    WRITE = "write"
    ACCESS = "access"
    BROWSE = "browse"
    # WFS/WMS/WPS permissions (https://www.ogc.org/standards/<OWS-type>)
    GET_CAPABILITIES = "getcapabilities"
    GET_MAP = "getmap"
    GET_FEATURE_INFO = "getfeatureinfo"
    GET_LEGEND_GRAPHIC = "getlegendgraphic"
    GET_METADATA = "getmetadata"
    GET_PROPERTY_VALUE = "getpropertyvalue"
    GET_FEATURE = "getfeature"
    GET_FEATURE_WITH_LOCK = "getfeaturewithlock"
    DESCRIBE_FEATURE_TYPE = "describefeaturetype"
    DESCRIBE_LAYER = "describelayer"
    DESCRIBE_PROCESS = "describeprocess"
    EXECUTE = "execute"
    LOCK_FEATURE = "lockfeature"
    TRANSACTION = "transaction"
    CREATE_STORED_QUERY = "createstoredquery"
    DROP_STORED_QUERY = "dropstoredquery"
    LIST_STORED_QUERIES = "liststoredqueries"
    DESCRIBE_STORED_QUERIES = "describestoredqueries"


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
    __slots__ = ["_name", "_access", "_scope", "_tuple", "_type", "_reason"]

    def __init__(self,
                 permission,    # type: AnyPermissionType
                 access=None,   # type: Optional[Union[Access, Str]]
                 scope=None,    # type: Optional[Union[Scope, Str]]
                 typ=None,      # type: Optional[PermissionType]
                 reason=None,   # type: Optional[Str]
                 ):             # type: (...) -> None
        """
        Initializes the permission definition, possibly using required conversion from other implementations.

        :param permission: Name of the permission, or any other implementation from which the name can be inferred.
        :param access: Effective behaviour of the permissions. Generally, grant or deny the specified permission.
        :param scope: Scope for which the permission affects hierarchical resources. Important for effective resolution.
        :param typ: Type of permission being represented. Informative only, does not impact behavior if omitted.
        :param reason:
            Slightly more indicative information on why the current permission-type has this value.
            Value should be either explicitly provided or will be inferred if converted from input PermissionTuple.

        .. seealso::
            :meth:`PermissionSet._convert`
        """
        tup = None
        if not isinstance(permission, Permission):
            perm_set = PermissionSet._convert(permission)
            if isinstance(permission, PermissionTuple):
                tup = permission
            elif isinstance(permission, PermissionSet):
                tup = permission.perm_tuple
            permission = perm_set.name
            access = perm_set.access if access is None else access
            scope = perm_set.scope if scope is None else scope
            typ = perm_set.type if perm_set.type is not None else typ
            reason = perm_set.reason if perm_set.reason is not None else reason
        self.name = permission
        self.access = access
        self.scope = scope
        self.type = typ
        self._tuple = tup  # type: Optional[PermissionTuple]   # reference to original item if available
        self._reason = reason

    def __eq__(self, other):
        # type: (Any) -> bool
        if not isinstance(other, PermissionSet):
            other = PermissionSet(other)
        return self.name == other.name and self.access == other.access and self.scope == other.scope

    def __ne__(self, other):
        # type: (Any) -> bool
        return not self.__eq__(other)

    def __lt__(self, other):
        # type: (Any) -> bool
        """
        Ascending sort of permission according to their name, access and scope modifiers.

        First sort by permission name alphabetically, followed by increasing *restrictive access* and increasing
        *range of scoped resources*.

        Using this sorting methodology, similar permissions by name are grouped together first, and permissions of same
        name with modifiers are then ordered, the first having less priority when selecting a single item to display
        with conflicting possibilities. Respecting :attr:`Access.DENY` is more important than :attr:`Access.ALLOW`
        (to protect the :term:`Resource`), and :attr:`Scope.MATCH` is *closer* to the actual :term:`Resource` than
        :attr:`Scope.RECURSIVE` permission received from a *farther* parent in the hierarchy.

        Sorted explicit string representation becomes::

            [name1]-[allow]-[match]
            [name1]-[allow]-[recursive]
            [name1]-[deny]-[match]
            [name1]-[deny]-[recursive]
            [name2]-[allow]-[match]
            [name2]-[allow]-[recursive]
            [name2]-[deny]-[match]
            [name2]-[deny]-[recursive]
            ...

        We then obtain two **crucial** ordering results:
            1. We can easily pick the last sorted item with highest resolution priority to find the final result of
               corresponding permissions.
               (note: final result for same user or group, their direct/inherited resolution is not considered here).
            2. Picking the first element with lowest priority also displays the permission that impacts the widest
               range of resources. For instance in Magpie UI, indicating that a permission as :attr:`Scope.RECURSIVE`
               is more verbose as it tell other resources under it are also receive the specified :class:`Access`
               modifier rather than only the punctual resource.

        .. warning::
            Alphabetically sorting permissions by string representation (implicit/explicit) is not equivalent to
            sorting them according to :term:`Permission` priority according to how modifiers are resolved. To obtain
            the prioritized sorting as strings, a list of :class:`PermissionSet` (with the strings as input) should be
            used to convert and correctly interpreted the raw strings, and then be converted back after sorting.

            .. code-block:: python

                # valid priority-sorted strings
                [str(perm) for perm in sorted(PermissionSet(p) for p in permission_strings)]

                # not equivalent to raw sorting
                list(sorted(permission_strings))
        """
        if not isinstance(other, PermissionSet):
            other = PermissionSet(other)
        if self.name != other.name:
            return self.name.value < other.name.value
        if self.access != other.access:
            return self.access == Access.ALLOW
        if self.scope != other.scope:
            return self.scope == Scope.MATCH
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
        perm_repr_template = "PermissionSet(name={}, access={}, scope={}, type={}{})"
        perm_type = self.type.value if self.type is not None else None
        perm_reason = ", reason={}".format(self.reason) if self.reason else ""
        return perm_repr_template.format(self.name.value, self.access.value, self.scope.value, perm_type, perm_reason)

    def like(self, other):
        # type: (Any) -> bool
        """
        Evaluates if one permission is *similar* to another permission definition regardless of *modifiers*.

        This is different than ``==`` operator which will evaluate *exactly* equal permission definitions.
        """
        if not isinstance(other, PermissionSet):
            other = PermissionSet(other)
        return self.name == other.name

    def json(self):
        # type: () -> PermissionDict
        """
        Obtains the JSON representation of this :class:`PermissionSet`.
        """
        perm = {
            "name": self.name.value,
            "access": self.access.value,
            "scope": self.scope.value,
            "type": self.type.value if self.type is not None else None,
        }
        if self.reason:
            perm.update({"reason": self.reason})
        return perm

    def webhook_params(self):
        # type: () -> JSON
        """
        Obtain JSON representation employed for :term:`Webhook` reference.
        """
        return {
            "permission": str(self),
            "permission.name": self.name.value,
            "permission.access": self.access.value,
            "permission.scope": self.scope.value,
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
    def reason(self):
        # type: () -> Optional[Str]
        """
        Indicative reason of the returned value defined by :meth:`type` or inferred by the :class:`PermissionTuple`.

        .. seealso::
            :meth:`combine`

        :returns:
            Single string that describes the reason (source) of the permission, or multiple strings if updated by
            combination of multiple permissions.
        """
        if self._reason is not None:
            return self._reason
        if self._tuple is None:
            return None
        if self._tuple.type == "user":
            self._reason = "user:{}:{}".format(self._tuple.user.id, self._tuple.user.user_name)
        if self._tuple.type == "group":
            self._reason = "group:{}:{}".format(self._tuple.group.id, self._tuple.group.group_name)
        return self._reason

    @reason.setter
    def reason(self, reason):
        # type: (Optional[Str]) -> None
        self._reason = reason

    @classmethod
    def resolve(cls,
                permission1,                        # type: ResolvablePermissionType
                permission2,                        # type: ResolvablePermissionType
                context=PermissionType.INHERITED,   # type: PermissionType
                multiple_choice=None,               # type: Optional[ResolvablePermissionType]
                ):                                  # type: (...) -> ResolvablePermissionType

        """
        Resolves provided permissions into a single one considering various modifiers and groups for a resource.

        Permissions **MUST** have the same :term:`Permission` name.

        By default (using :paramref:`same_resources`), the associated :term:`Resource` on which the two compared
        permissions are applied on should also be the same (especially during local :term:`Inherited Permissions`
        resolution). This safeguard must be disabled for :term:`Effective Permissions` that specifically handles
        multi-level :term:`Resource` resolution.

        The comparison considers both the :class:`Access` and :class:`Scope` of :term:`Inherited Permissions` of the
        :term:`User`, as well as its :term:`Group` memberships sorted by their priority.

        .. seealso::
            - :meth:`magpie.services.ServiceInterface.effective_permissions`
            - :func:`magpie.api.management.user.user_utils.combine_user_group_permissions`
            - :meth:`PermissionSet.__lt__`
        """
        if not isinstance(permission1, PermissionSet):
            permission1 = PermissionSet(permission1)
        if not isinstance(permission2, PermissionSet):
            permission2 = PermissionSet(permission2)
        # both permissions must contain the user or group reference from the original permission tuple to allow compare
        # they must also have the same permission name to actually resolving the one to preserve
        if permission1.name != permission2.name or not (permission1.perm_tuple and permission2.perm_tuple):
            raise ValueError("Invalid resolution attempt between two incomparable permissions.")
        # when resolving (local inherited resolution), only one user permission on same resource is possible (by design)
        # hierarchical/effective resolution of resources can differ
        if context == PermissionType.INHERITED and (
                (permission1.perm_tuple.resource is not permission2.perm_tuple.resource) or
                (permission1.type == PermissionType.DIRECT and permission2.type == PermissionType.DIRECT)):
            raise ValueError("Invalid inherited resolution attempt expected same resources but contain invalid values.")

        # user direct permission always have priority
        if permission1.type == PermissionType.DIRECT:
            return permission1
        if permission2.type == PermissionType.DIRECT:
            return permission2
        # when only comparing groups, priority dictates the result
        priority1 = permission1.group_priority
        priority2 = permission2.group_priority
        if priority1 > priority2:
            return permission1
        if priority1 < priority2:
            return permission2
        # same group priority are resolved according to corresponding permission names/access/scope (__lt__)
        if permission1 == permission2:
            # if the two different groups have the exact same resolution value,
            # indicate that multiple groups resolve into the same access, unless a choice was provided
            permission1.reason = multiple_choice.reason if multiple_choice else PERMISSION_REASON_MULTIPLE
            return permission1  # preserved group in perm-tuple doesn't matter as they are equivalent
        # otherwise return whichever group permission has higher resolution value
        return permission2 if permission1 < permission2 else permission1

    @property
    def group_priority(self):
        # type: () -> Optional[GroupPriority]
        """
        Priority accessor in case of group inherited permission resolved by :class:`PermissionTuple`.
        """
        if self._tuple is not None and self.type == PermissionType.INHERITED:
            return self._tuple.group.priority
        return None

    @property
    def perm_tuple(self):
        # type: () -> Optional[PermissionTuple]
        """
        Get the original :class:`PermissionTuple` if available (:class:`PermissionSet` must have been created by one).
        """
        return self._tuple

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
        if self._type is None and self._tuple is not None:
            if self._tuple.type == "user":
                self._type = PermissionType.DIRECT
            if self._tuple.type == "group":
                self._type = PermissionType.INHERITED
        return self._type

    @type.setter
    def type(self, typ):
        self._type = PermissionType.get(typ)

    @classmethod
    def _convert(cls, permission):
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
                       force_unique=True,       # type: bool
                       ):                       # type: (...) -> Dict[Str, Union[List[Str], PermissionDict, Str]]
    """
    Obtains the formatted permission representations after validation that each of their name is a known member of
    :class:`Permission` enum, and optionally with modifiers as defined by :class:`PermissionSet`.

    The returned lists are sorted alphabetically by permission *name*, and then in order of resolution priority (from
    highest to lowest) for each subset or corresponding *name*.

    The permissions are cleaned from any duplicate entries, unless :paramref:`force_unique` is specified to allow it.
    If no or empty :paramref:`permissions` is provided, empty lists are returned.

    .. note::
        Field ``permission_names`` provides both the *older* implicit permission names and the *newer* explicit name
        representation. For this reason, there will be semantically "duplicate" permissions in that list, but there
        will not be any literal string duplicates. Implicit names are immediately followed by their explicit name,
        unless implicit names do not apply for the given permission (e.g.: when :attr:`Access.DENY` did not exist).
        Only detailed and explicit JSON representations are provided in the ``permissions`` list.

    When :paramref:`permission_type` is equal to :attr:`PermissionType.ALLOWED`, the collection of every applicable
    :class:`PermissionSet` is automatically generated by expanding all combinations of :class:`Access` and
    :class:`Scope` with every provided :class:`Permission` name in :paramref:`permissions`. This allows more concise
    definition of allowed permissions under :class:`magpie.services.Services` and their children :term:`Resource` by
    only defining :class:`Permission` names without manually listing all variations of :class:`PermissionSet`.

    For other :paramref:`permission_type` values, which represent :term:`Applied Permissions` only explicitly
    provided :paramref:`permissions` are returned, to effectively return the collection of *active* permissions.

    :param permissions: multiple permissions of any implementation and type, to be rendered both as names and JSON.
    :param permission_type: indication of the represented permissions to be formatted, for informative indication.
    :param force_unique: whether to remove duplicate entries by association of name, access and scope or not.
    :returns: JSON with the permissions listed as implicit+explicit names, as permission set objects, and their type.
    """
    json_perms = []
    bw_perm_names = []  # to preserve insert order
    if permission_type is None:
        permission_type = PermissionType.ALLOWED
    if permissions:
        bw_perm_unique = set()  # for quick remove of duplicates
        perms_list = [PermissionSet(perm, typ=permission_type) for perm in permissions]
        if force_unique:
            perms_list = set(perms_list)
        perms_list = sorted(perms_list)
        if permission_type == PermissionType.ALLOWED:
            unique_names = {perm.name for perm in perms_list}  # trim out any extra variations, then build full list
            perms_list = sorted([PermissionSet(name, access, scope, PermissionType.ALLOWED)
                                 for name, access, scope in itertools.product(unique_names, Access, Scope)])
        for perm in perms_list:
            implicit_perm = perm.implicit_permission
            explicit_perm = perm.explicit_permission
            if implicit_perm is not None and implicit_perm not in bw_perm_unique:
                bw_perm_names.append(implicit_perm)
                bw_perm_unique.add(implicit_perm)
            if explicit_perm not in bw_perm_names:
                bw_perm_names.append(explicit_perm)
                bw_perm_unique.add(explicit_perm)
        json_perms = [perm.json() for perm in perms_list]
    for perm in json_perms:
        perm.setdefault("type", permission_type.value)
    return {
        "permission_names": bw_perm_names,  # backward compatible + explicit names
        "permissions": json_perms           # explicit objects with types
    }
