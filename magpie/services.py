import abc
import re
from typing import TYPE_CHECKING

import six
from beaker.cache import Cache, cache_region, cache_regions, region_invalidate
from pyramid.httpexceptions import HTTPBadRequest, HTTPInternalServerError, HTTPNotImplemented
from pyramid.security import ALL_PERMISSIONS, DENY_ALL
from sqlalchemy.inspection import inspect as sa_inspect
from ziggurat_foundations.models.base import get_db_session
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.permissions import permission_to_pyramid_acls

from magpie import models
from magpie.api import exception as ax
from magpie.constants import get_constant
from magpie.db import get_connected_session
from magpie.owsrequest import ows_parser_factory
from magpie.permissions import (
    PERMISSION_REASON_ADMIN,
    PERMISSION_REASON_DEFAULT,
    Access,
    Permission,
    PermissionSet,
    PermissionType,
    Scope
)
from magpie.utils import classproperty, fully_qualified_name, get_logger

LOGGER = get_logger(__name__)
if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Collection, Dict, List, Optional, Set, Tuple, Type, Union

    from pyramid.request import Request

    from magpie.typedefs import (
        AccessControlListType,
        MultiResourceRequested,
        PermissionRequested,
        ResourceTypePermissions,
        ServiceConfiguration,
        ServiceOrResourceType,
        Str,
        TargetResourceRequested
    )


class ServiceMeta(type):
    @property
    def resource_types(cls):
        # type: (Type[ServiceInterface]) -> List[Type[models.Resource]]
        """
        Allowed resources type classes under the service.
        """
        return list(cls.resource_types_permissions)

    @property
    def resource_type_names(cls):
        # type: (Type[ServiceInterface]) -> List[Str]
        """
        Allowed resources type names under the service.
        """
        # pylint: disable=E1133     # is iterable but detected as not like one
        return [res.resource_type_name for res in cls.resource_types]

    @property
    def child_resource_allowed(cls):
        # type: (Type[ServiceInterface]) -> bool
        """
        Lists all resources allowed *somewhere* within its resource hierarchy under the service.

        .. note::
            Resources are not necessarily all allowed *directly* under the service.
            This depends on whether :attr:`ServiceInterface.child_structure_allowed` is defined or not.
            If not defined, resources are applicable anywhere.
            Otherwise, they must respect the explicit structure definitions.

        .. seealso::
             Use :meth:`ServiceInterface.nested_resource_allowed` to obtain only scoped types allowed under a
             given resource considering allowed path structures.
        """
        return len(cls.resource_types) > 0


@six.add_metaclass(ServiceMeta)
class ServiceInterface(object):
    @property
    @abc.abstractmethod
    def service_type(self):
        # type: () -> Optional[Str]
        """
        Service type identifier (required, unique across implementation).
        """
        raise NotImplementedError

    permissions = []  # type: List[Permission]
    """
    Permission allowed directly on the service as top-level resource.
    """

    resource_types_permissions = {}  # type: ResourceTypePermissions
    """
    Mapping of resource types to lists of permissions defining allowed children resource permissions under the service.
    """

    child_structure_allowed = {}  # type: Dict[Type[ServiceOrResourceType], List[Type[models.Resource]]]
    """
    Control mapping of resource types limiting the allowed structure of nested children resources.

    When not defined, any nested resource type combination is allowed if they themselves allow children resources.
    Otherwise, nested child resource under the service can only be created at specific positions within the hierarchy
    that matches exactly one of the defined control conditions.

    For example, the below definition allows only resources typed ``route`` directly under the service.
    The following nested resource under that first-level ``route`` can then be either another ``route`` followed
    by a child ``process`` or directly a ``process``. Because ``process`` type doesn't allow any children resource
    (see :attr:`models.Process.child_resource_allowed`), those are the only allowed combinations (cannot further nest
    resources under the final ``process`` resource).

    .. code-block:: python

        child_structure_allowed = {
            models.Service: [models.Route],
            models.Route: [models.Route, models.Process],
            models.Process: [],
        }

    .. seealso::
        - Validation of allowed nested children resource insertion of a given type under a parent resource is provided
          by :meth:`ServiceInterface.validate_nested_resource_type` that employs :attr:`child_structure_allowed`.
        - Listing of allowed resource types scoped under a given child resource within the hierarchy is provided
          by :meth:`ServiceInterface.nested_resource_allowed`.
    """

    _config = None  # type: Optional[ServiceConfiguration]  # for optimization to avoid reload and parsing each time
    configurable = False
    """
    Indicates if the service supports custom configuration.
    """

    def __init__(self, service, request):
        # type: (models.Service, Optional[Request]) -> None
        """
        Initialize the service.

        :param service: Base service resource that must be handled by this service implementation.
        :param request: Active request to handle requested resources, permissions and effective access.
            The request can be omitted if basic service definition details are to be retrieved.
            It is mandatory for any ``requested`` or ``effective`` component that should be resolved.
        """
        self.service = service          # type: models.Service
        self.request = request          # type: Request
        self._flag_acl_cached = {}      # type: Dict[Tuple[Str, Str, Str, Optional[int]], bool]

    def __str__(self):
        return "<Service [{}] name={} type={} id={}>".format(
            type(self).__name__, self.service_type, self.service.resource_name, self.service.resource_id
        )

    @abc.abstractmethod
    def permission_requested(self):
        # type: () -> PermissionRequested
        """
        Defines how to interpret the incoming request into :class:`Permission` definitions for the given service.

        Each service must implement its own definition.
        The method must specifically define how to convert generic request path, query, etc. elements into permissions
        that match the service and its children resources.

        If ``None`` is returned, the :term:`ACL` will effectively be resolved to denied access.
        Otherwise, one or more returned :class:`Permission` will indicate which permissions should be looked for to
        resolve the :term:`ACL` of the authenticated user and its groups.

        If the request cannot be parsed for any reason to retrieve needed parameters (e.g.: Bad Request),
        the :exception:`HTTPBadRequest` can be raised to indicate specifically the cause, which will
        help :class:`magpie.adapter.magpieowssecurity.MagpieOWSSecurity` create a better response with
        the relevant error details.
        """
        raise NotImplementedError("missing implementation of request permission converter")

    @abc.abstractmethod
    def resource_requested(self):
        # type: () -> MultiResourceRequested
        """
        Defines how to interpret the incoming request into the targeted :class:`model.Resource` for the given service.

        Each service must implement its own definition.

        The expected return value must be either of the following::

            - List<(target-resource, target?)>  When multiple resources need validation ('target?' as below for each).
            - (target-resource, True)           when the exact resource is found according to request parsing.
            - (parent-resource, False)          when any parent of the resource is found according to request parsing.
            - None                              when invalid request or not found resource.

        The ``parent-resource`` should indicate the *closest* higher-level resource in the hierarchy that would nest
        the otherwise desired ``target-resource``. The idea behind this is that `Magpie` will be able to resolve the
        effective recursive scoped permission even if not all corresponding resources were explicitly defined in the
        database.

        For example, if the request *would* be interpreted with the following hierarchy after service-specific
        resolution::

            ServiceA
                Resource1         <== closest *existing* parent resource
                    [Resource2]   <== target (according to service/request resolution), but not existing in database

        A permission defined as Allow/Recursive on ``Resource1`` should *normally* allow access to ``Resource2``. If
        ``Resource2`` is not present in the database though, it cannot be looked for, and the corresponding ACL cannot
        be generated. Because the (real) protected service using `Magpie` can have a large and dynamic hierarchy, it
        is not convenient to enforce perpetual sync between it and its resource representation in `Magpie`. Using
        ``(parent-resource, False)`` will allow resolution of permission from the closest available parent.

        .. note::
            In case of ``parent-resource`` returned, only `recursive`-scoped permissions will be considered, since the
            missing ``target-resource`` is the only one that should be checked for `match`-scoped permissions. For this
            reason, the service-specific implementation should preferably return the explicit `target` resource whenever
            possible.

        If the returned resource is ``None``, the ACL will effectively be resolved to denied access. This can be used
        to indicate failure to retrieve the expected resource or that corresponding resource does not exist. Otherwise,
        this method implementation should convert any request path, query parameters, etc. into an existing resource.

        If a list of ``(target-resource, target?)`` is returned, all of those resources should individually perform
        :term:`Effective Resolution` and should **ALL** simultaneously be granted access to let the request through.
        This can be used to resolve ambiguous or equivalent parameter combinations from parsing the request, or to
        validate access to parameters that allow multi-resource references using some kind of list value representation.

        .. seealso::
            - :meth:`_get_acl` for :term:`Effective Resolution` of over multiple :term:`Resource` references.
            - :meth:`effective_permissions` for :term:`Effective Resolution`  of a single :term:`Resource`.

        :returns:
            One or many tuple of reference resource (target/parent),
            and explicit match status of the corresponding resource (True/False)
        """
        raise NotImplementedError

    def user_requested(self):
        user = self.request.user
        if not user:
            session = get_connected_session(self.request)
            anonymous = get_constant("MAGPIE_ANONYMOUS_USER", self.request)
            user = UserService.by_user_name(anonymous, db_session=session)
            if user is None:
                raise RuntimeError("No Anonymous user in the database")
        return user

    @property
    def __acl__(self):
        # type: () -> AccessControlListType
        """
        Access Control List (:term:`ACL`) formed of :term:`ACE` defining combinations rules to grant or refuse access.

        Each :term:`ACE` is defined as ``(outcome, user/group, permission)`` tuples.
        Called by the configured Pyramid :class:`pyramid.authorization.ACLAuthorizationPolicy`.

        Caching is automatically handled according to configured application settings and whether the specific ACL
        combination being requested was already processed recently.
        """
        if "acl" not in cache_regions:
            cache_regions["acl"] = {"enabled": False}
        user_id = None if self.request.user is None else self.request.user.id
        cache_keys = (self.service.resource_name, self.request.method, self.request.path_qs, user_id)
        LOGGER.debug("Cache keys: %s", list(cache_keys))
        self._flag_acl_cached[cache_keys] = True  # remains true if not reset by run '_get_acl_cached', hence cached
        if self.request.headers.get("Cache-Control") == "no-cache":
            LOGGER.debug("Cache invalidation requested. Removing items from ACL region: %s", list(cache_keys))
            region_invalidate(self._get_acl_cached, "acl", *cache_keys)
        acl = self._get_acl_cached(*cache_keys)
        if self._flag_acl_cached[cache_keys]:
            LOGGER.warning("Using cached ACL")
        return acl

    @cache_region("acl")
    def _get_acl_cached(self, service_name, request_method, request_path, user_id):
        # type: (Str, Str, Str, Optional[int]) -> AccessControlListType
        """
        Cache this method with :py:mod:`beaker` based on the provided caching key parameters.

        If the cache is not hit (expired timeout or new key entry), calls :meth:`ServiceInterface.get_acl` to retrieve
        effective permissions of the requested resource and specific permission for the applicable service and user
        executing the request.

        .. note::
            Function arguments are required to generate caching keys by which cached elements will be retrieved.
            Actual arguments are not needed as we employ stored objects in the instance.

        .. warning::
            Anything within this method or any underlying calls that can potentially retrieve database contents,
            whether for direct object or dynamically generated relationships (eg: ``user.groups``) must attempt
            to reestablish any detached or invalid session/transaction due to the potentially desynchronized
            references between objects before/after both incoming ``service`` and this ``acl`` cache regions.

        .. seealso::
            - :meth:`ServiceInterface.permission_requested`
            - :meth:`ServiceInterface.resource_requested`
            - :meth:`ServiceInterface.user_requested`
        """
        self._flag_acl_cached[(service_name, request_method, request_path, user_id)] = False

        # attempt to catch any missing reconnect or detect closed transaction if needed for following steps
        # store in 'request.db' reference since service implementations don't always use 'get_connected_session'
        self.request.db = get_connected_session(self.request)

        permissions = self.permission_requested()
        if permissions is None:
            return [DENY_ALL]

        target_resources = self.resource_requested()
        if not target_resources:
            return [DENY_ALL]
        if not isinstance(target_resources, list):
            if not isinstance(target_resources, tuple):
                resource = target_resources
                is_target = False
            else:
                resource, is_target = target_resources
            target_resources = [(resource, is_target)]
        if any(res[0] is None for res in target_resources):
            return [DENY_ALL]

        if not isinstance(permissions, (list, set, tuple)):
            permissions = {permissions}
        user = self.user_requested()

        return self._get_acl(user, target_resources, permissions)

    def _get_acl(self, user, resources, permissions):
        # type: (models.User, MultiResourceRequested, Collection[Permission]) -> AccessControlListType
        """
        Resolves resource-tree and user/group inherited permissions into simplified :term:`ACL` of requested resources.

        Contrary to :meth:`effective_permissions` that can be resolved only for individual :term:`Resource`, :term:`ACL`
        is involved during actual request access, which could refer to multiple :term:`Resource` references or distinct
        :term:`Permission` names if the identified parent :term:`Service` supports it.

        When more than one item is specified for validation (any combination of :term:`Resource` or :term:`Permission`),
        **ALL** of them must be granted access to resolve as :data:`Access.ALLOW`. Any denied access blocks the whole
        set of requested elements.

        .. seealso::
            - Core :term:`Permission` resolution rules of a single :term:`Resource` using :meth:`effective_permissions`.
            - Support of multi-:term:`Resource` references defined by returned values of :meth:`resource_requested`
              for individual :class:`ServiceInterface` implementations.
        """
        # avoid useless effective resolution re-computation if duplicates are found
        target_resources = list(dict.fromkeys(resources))  # set(), but preserving order
        allowed_ace = []
        for resource, is_target in target_resources:

            # only 1 entry per (permission-name, resource) possible after effective resolution for each resource
            # since distinct resources are being processed, user/group precedence and group priority doesn't matter
            # resulting Allow/Deny for each case is the "highest priority" for each applicable resource individually
            res_access_perms = self.effective_permissions(user, resource, permissions, is_target)
            for perm in res_access_perms:
                # if any resource or any permission indicates deny,
                # break out to avoid useless computation (block all)
                if perm.access == Access.DENY:
                    return [perm.ace(self.request.user)]
                allowed_ace.append(perm.ace(self.request.user))

        if not allowed_ace:
            return [DENY_ALL]
        return allowed_ace

    def _get_connected_object(self, obj):
        # type: (Union[ServiceOrResourceType, models.User]) -> Optional[ServiceOrResourceType]
        """
        Retrieve the object with an active session and attached state by refreshing connection with request session.

        This operation is required mostly in cases of mismatching references between cached and active objects obtained
        according to timing of requests and whether caching took placed between them, and for different caching region
        levels (service, ACL or both). It also attempts to correct and encountered problems due to concurrent requests.
        """
        db_session = get_connected_session(self.request)

        # Reconnect the referenced object to active database session if it is detached or inactive.
        # - This can happen during mismatching sources of cached objects for service/ACL region combinations,
        #   where service/resource data is available from cache but not associated with an appropriate session state.
        # - Since this operation is being computed, ACL is not yet cached (or was reset before service cache was).
        #   The service/resource must be refreshed regardless of cache to resolve it with other object references.
        # - Because of possibly reconnected objects from previous calls to this method, other objects might also need
        #   to be synced with the same database session.
        # In case the DB session was inactive and a new one was recreated above, also ensure that the resource did not
        # already have an handle referring to the old session.
        obj_session = get_db_session(session=None, obj=obj)
        if isinstance(obj, models.User):
            obj_type = "user"
        elif isinstance(obj, models.Service):
            obj_type = "service"
        else:
            obj_type = "resource"
        if obj_session is None or not obj_session.is_active:
            if obj_session is None:
                LOGGER.debug("Reconnect cached %s [%s] with active request session (missing session).", obj_type, obj)
            else:
                LOGGER.debug("Reconnect cached %s [%s] with active request session (inactive session).", obj_type, obj)
            if obj_type == "user":
                obj_connect = UserService.by_id(obj.id, db_session=db_session)
            else:
                obj_connect = ResourceService.by_resource_id(obj.resource_id, db_session=db_session)
            if obj_connect is None:
                LOGGER.warning("Reconnect cached %s to active session failed!", obj_type)
                LOGGER.debug("Session: %s, Resource: %s, Type: %s", db_session, obj, obj_type)
                return None
            obj = obj_connect
        # Merge retrieved resource to the active session if not already attached.
        state = sa_inspect(obj)
        if state.detached:
            LOGGER.debug("Reconnect cached %s [%s] with active request session (detached state).", obj_type, obj)
            obj = db_session.merge(obj)
            state = sa_inspect(obj)

        LOGGER.debug("Object [%s] is [%s] %s session [%s, active=%s, id=%s].",
                     obj, "detached" if state.detached else "attached", "from" if state.detached else "to",
                     state.session, state.session.is_active, state.session_id)
        return obj

    def _get_request_path_parts(self):
        # type: () -> Optional[List[Str]]
        """
        Obtain the :attr:`request` path parts striped of anything prior to the referenced :attr:`service` name.
        """
        path_parts = self.request.path.rstrip("/").split("/")
        svc_name = self.service.resource_name
        if svc_name not in path_parts:
            return None
        svc_idx = path_parts.index(svc_name)
        return path_parts[svc_idx + 1:]

    def get_config(self):
        # type: () -> ServiceConfiguration
        """
        Obtains the custom configuration of the registered service.
        """
        return self.service.configuration

    @classmethod
    def get_resource_permissions(cls, resource_type_name):
        # type: (Str) -> List[Permission]
        """
        Obtains the allowed permissions of the service's child resource fetched by resource type name.
        """
        for res in cls.resource_types_permissions:
            if res.resource_type_name == resource_type_name:
                return cls.resource_types_permissions[res]
        return []

    @classmethod
    def validate_nested_resource_type(cls, parent_resource, child_resource_type):
        # type: (ServiceOrResourceType, Str) -> bool
        """
        Validate whether a new child resource type is allowed under the parent resource under the service.

        :param parent_resource: Parent under which the new resource must be validated. This can be the service itself.
        :param child_resource_type: Type to validate at the position defined under the parent resource.
        :return: status indicating if insertion is allowed for this type and at this parent position.
        """
        child_resources = cls.nested_resource_allowed(parent_resource)
        if not child_resources:
            return False
        child_allow_types = [res.resource_type_name for res in child_resources]
        return child_resource_type in child_allow_types

    @classmethod
    def nested_resource_allowed(cls, parent_resource):
        # type: (ServiceOrResourceType) -> List[Type[models.Resource]]
        """
        Obtain the nested resource types allowed as children resource within structure definitions.
        """
        if not cls.child_resource_allowed:
            return []
        if not get_resource_child_allowed(parent_resource):
            return []
        # if undefined control structures, any combination is allowed (original behaviour)
        if not cls.child_structure_allowed:
            return cls.resource_types
        child_allow_types = [res.resource_type_name for res in cls.child_structure_allowed]
        if parent_resource.resource_type_name not in child_allow_types:
            return []
        return cls.child_structure_allowed[type(parent_resource)]

    def allowed_permissions(self, resource):
        # type: (ServiceOrResourceType) -> List[Permission]
        """
        Obtains the allowed permissions for or under the service according to provided service or resource.
        """
        if resource.resource_type == "service" and resource.type == self.service_type:
            return self.permissions
        return self.get_resource_permissions(resource.resource_type)

    def effective_permissions(self,
                              user,                     # type: models.User
                              resource,                 # type: ServiceOrResourceType
                              permissions=None,         # type: Optional[Collection[Permission]]
                              allow_match=True,         # type: bool
                              ):                        # type: (...) -> List[PermissionSet]
        """
        Obtains the :term:`Effective Resolution` of permissions the user has over the specified resource.

        Recursively rewinds the resource tree from the specified resource up to the top-most parent service the resource
        resides under (or directly if the resource is the service) and retrieve permissions along the way that should be
        applied to children when using scoped-resource inheritance. Rewinding of the tree can terminate earlier when
        permissions can be immediately resolved such as when more restrictive conditions enforce denied access.

        Both user and group permission inheritance is resolved simultaneously to tree hierarchy with corresponding
        allow and deny conditions. User :term:`Direct Permissions <Direct Permission>` have priority over all its groups
        :term:`Inherited Permissions <Inherited Permission>`, and denied permissions have priority over allowed access
        ones.

        All applicable permissions on the resource (as defined by :meth:`allowed_permissions`) will have their
        resolution (Allow/Deny) provided as output, unless a specific subset of permissions is requested using
        :paramref:`permissions`. Other permissions are ignored in this case to only resolve requested ones.
        For example, this parameter can be used to request only ACL resolution from specific permissions applicable
        for a given request, as obtained by :meth:`permission_requested`.

        Permissions scoped as `match` can be ignored using :paramref:`allow_match`, such as when the targeted resource
        does not exist.

        .. seealso::
            - :meth:`ServiceInterface.resource_requested`

        :param user: :term:`User` for which to perform :term:`Effective Resolution`.
        :param resource: :term:`Resource` onto which access must be resolved.
        :param permissions: List of :term:`Permission` for which to perform the resolution.
        :param allow_match: Indicate if the specific :term:`Resource` was matched to allow :data:`Scope.MATCH` handling.
        :returns: Resolved set :term:`Effective Permission` for specified parameter combinations.
        """
        if not permissions:
            permissions = self.allowed_permissions(resource)
        requested_perms = set(permissions)  # type: Set[Permission]
        effective_perms = dict()            # type: Dict[Permission, PermissionSet]

        db_session = get_connected_session(self.request)
        user = self._get_connected_object(user)  # groups dynamically populated fail if not connected (for admin check)
        LOGGER.debug("Resolving effective permission for: [user: %s, resource: %s, permissions: %s, match: %s]",
                     user, resource, list(permissions), allow_match)

        # immediately return all permissions if user is an admin
        admin_group = get_constant("MAGPIE_ADMIN_GROUP", self.request)
        admin_group = GroupService.by_group_name(admin_group, db_session=db_session)
        if admin_group in user.groups:  # noqa
            LOGGER.debug("Resolved by early detection of admin group membership. Full access granted.")
            return [
                PermissionSet(perm, access=Access.ALLOW, scope=Scope.MATCH,
                              typ=PermissionType.EFFECTIVE, reason=PERMISSION_REASON_ADMIN)
                for perm in permissions
            ]

        # level at which last permission was found, -1 if not found
        # employed to resolve with *closest* scope and for applicable 'reason' combination on same level
        effective_level = dict()  # type: Dict[Permission, Optional[int]]
        current_level = 1   # one-based to avoid ``if level:`` check failing with zero
        full_break = False
        # current and parent resource(s) recursive-scope
        while resource is not None and not full_break:  # bottom-up until service is reached
            LOGGER.debug("Resolving for (sub-)resource: [%s]", resource)
            resource = self._get_connected_object(resource)
            if resource is None:
                LOGGER.warning("Resource 'None' after reconnection attempt. Early stop effective resolution loop.")
                break

            # include both permissions set in database as well as defined directly on resource
            cur_res_perms = ResourceService.perms_for_user(resource, user, db_session=db_session)
            cur_res_perms.extend(permission_to_pyramid_acls(resource.__acl__))

            for perm_name in requested_perms:
                if full_break:
                    break
                for perm_tup in cur_res_perms:
                    perm_set = PermissionSet(perm_tup)

                    # if user is owner (directly or via groups), all permissions are set,
                    # but continue processing this resource until end in case user explicit deny reverts it
                    if perm_tup.perm_name == ALL_PERMISSIONS:
                        # FIXME:
                        #   This block needs to be validated if support of ownership rules are added.
                        #   Conditions must be revised according to wanted behaviour...
                        #   General idea for now is that explict user/group deny should be prioritized over resource
                        #   ownership permissions since these can be attributed to *any user* while explicit deny are
                        #   definitely set by an admin-level user.
                        for perm in requested_perms:
                            if perm_set.access == Access.DENY:
                                all_perm = PermissionSet(perm, perm_set.access, perm.scope, PermissionType.OWNED)
                                effective_perms[perm] = all_perm
                            else:
                                all_perm = PermissionSet(perm, perm_set.access, perm.scope, PermissionType.OWNED)
                                effective_perms.setdefault(perm, all_perm)
                        full_break = True
                        break
                    # skip if the current permission must not be processed (at all or for the moment until next 'name')
                    if perm_set.name not in requested_perms or perm_set.name != perm_name:
                        continue
                    # only first resource can use match (if even enabled with found one), parents are recursive-only
                    if not allow_match and perm_set.scope == Scope.MATCH:
                        continue
                    # pick the first permission if none was found up to this point
                    prev_perm = effective_perms.get(perm_name)
                    scope_level = effective_level.get(perm_name)
                    if not prev_perm:
                        LOGGER.debug("Found permission [level=%s]: %r (first occurrence)", current_level, perm_set)
                        effective_perms[perm_name] = perm_set
                        effective_level[perm_name] = current_level
                        continue

                    # user direct permissions have priority over inherited ones from groups
                    # if inherited permission was found during previous iteration, override it with direct permission
                    if perm_set.type == PermissionType.DIRECT:
                        # - reset resolution scope of previous permission attributed to group as it takes precedence
                        # - since there can't be more than one user permission-name per resource on a given level,
                        #   scope resolution is done after applying this *closest* permission, ignore higher level ones
                        if prev_perm.type == PermissionType.INHERITED or not scope_level:
                            LOGGER.debug("Found permission [level=%s]: %r", current_level, perm_set)
                            effective_perms[perm_name] = perm_set
                            effective_level[perm_name] = current_level
                        continue  # final decision for this user, skip any group permissions

                    # resolve prioritized permission according to ALLOW/DENY, scope and group priority
                    # (see 'PermissionSet.resolve' method for extensive details)
                    # skip if last permission is not on group to avoid redundant USER > GROUP check processed before
                    if prev_perm.type == PermissionType.INHERITED:
                        # - If new permission to process is done against the previous permission from *same* tree-level,
                        #   there is a possibility to combine equal priority groups. In such case, reason is 'MULTIPLE'.
                        # - If not of equal priority, the appropriate permission is selected and reason is overridden
                        #   accordingly by the new higher priority permission.
                        # - If no permission was defined at all (first occurrence), also set it using current permission
                        if scope_level in [None, current_level]:
                            resolved_perm = PermissionSet.resolve(perm_set, prev_perm, context=PermissionType.EFFECTIVE)
                            LOGGER.debug("Found permission [level=%s]: %r", current_level, resolved_perm)
                            effective_perms[perm_name] = resolved_perm
                            effective_level[perm_name] = current_level
                        # - If new permission is at *different* tree-level, it applies only if the group has higher
                        #   priority than the previous one, to respect the *closest* scope to the target resource.
                        #   Same priorities are ignored as they were already resolved by *closest* scope above.
                        # - Reset scope level with new permission such that another permission of same group priority as
                        #   that could be processed in next iteration can be compared against it, to resolve 'access'
                        #   priority between them.
                        elif perm_set.group_priority > prev_perm.group_priority:
                            LOGGER.debug("Found permission [level=%s]: %r (higher priority)", current_level, perm_set)
                            effective_perms[perm_name] = perm_set
                            effective_level[perm_name] = current_level

            # don't bother moving to parent if everything is resolved already
            #   can only assume nothing left to resolve if all permissions are direct on user (highest priority)
            #   if any found permission is group inherited, higher level user permission could still override it
            if (len(effective_perms) == len(requested_perms) and
                    all(perm.type == PermissionType.DIRECT for perm in effective_perms.values())):
                LOGGER.debug("Found permission has highest possible priority. Stopping search.")
                break
            # otherwise, move to parent if any available, since we are not done rewinding the resource tree
            allow_match = False  # reset match not applicable anymore for following parent resources
            current_level += 1
            if resource.parent_id:
                resource = ResourceService.by_resource_id(resource.parent_id, db_session=db_session)
            else:
                LOGGER.debug("No more children resources to process. Stopping search.")
                resource = None

        # set deny for all still unresolved permissions from requested ones
        resolved_perms = set(effective_perms)
        missing_perms = set(permissions) - resolved_perms
        final_perms = set(effective_perms.values())
        for perm_name in missing_perms:
            perm = PermissionSet(perm_name, access=Access.DENY, scope=Scope.MATCH,
                                 typ=PermissionType.EFFECTIVE, reason=PERMISSION_REASON_DEFAULT)
            LOGGER.debug("Adding missing permission: %s (requested)", perm)
            final_perms.add(perm)
        final_perms = list(final_perms)
        LOGGER.debug("Resolved applied permissions: %s", final_perms)

        # enforce type and scope (use MATCH to make it explicit that it applies specifically for this resource)
        for perm in final_perms:
            perm.type = PermissionType.EFFECTIVE
            perm.scope = Scope.MATCH

        LOGGER.debug("Resolved effective permissions: %s", final_perms)
        return final_perms


class ServiceOWS(ServiceInterface):
    """
    Generic request-to-permission interpretation method of various ``OGC Web Service`` (OWS) implementations.
    """

    params_expected = []  # type: List[Str]
    """
    Request query parameters that are expected and should be preprocessed by parsing the submitted request.
    """

    def __init__(self, service, request):
        # type: (models.Service, Request) -> None
        self._request = None
        self.parser = None
        super(ServiceOWS, self).__init__(service, request)  # sets request, which in turn parses it with below setter

    def _get_request(self):
        # type: () -> Request
        return self._request

    def _set_request(self, request):
        # type: (Request) -> None
        self._request = request
        if request is None:
            return  # avoid error parsing undefined request
        # must reset the parser from scratch if request changes to ensure everything is updated with new inputs
        self.parser = ows_parser_factory(request)
        self.parser.parse(type(self).params_expected)  # run parsing to obtain guaranteed lowercase parameters

    request = property(_get_request, _set_request)

    @property
    @abc.abstractmethod
    def service_base(self):
        # type: () -> Str
        """
        Name of the base :term:`OWS` functionality serviced by `Geoserver`.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def resource_requested(self):
        # type: () -> MultiResourceRequested
        raise NotImplementedError

    def permission_requested(self):
        # type: () -> PermissionRequested
        try:
            req = self.parser.params["request"]
            perm = Permission.get(str(req).lower())
            ax.verify_param(
                perm, not_none=True, param_name="request", http_error=HTTPBadRequest,
                content={"service": self.service.resource_name, "type": self.service_type, "value": req},
                msg_on_fail=(
                    "Missing or unknown 'Permission' inferred from OWS 'request' parameter: [{!s}]. ".format(req) +
                    "Unable to resolve the requested access for service: [{!s}].".format(self.service.resource_name)
                )
            )
            if perm not in self.permissions:
                return None
            return perm
        except KeyError as exc:
            raise NotImplementedError("Exception: [{!r}] for class '{}'.".format(exc, type(self)))


class ServiceWPS(ServiceOWS):
    """
    Service that represents a ``Web Processing Service`` endpoint.
    """
    service_base = "wps"
    service_type = "wps"

    permissions = [
        Permission.GET_CAPABILITIES,
        # following don't make sense if 'MATCH' directly on Service,
        # but can be set with 'RECURSIVE' for all Process children resources
        Permission.DESCRIBE_PROCESS,
        Permission.EXECUTE,
    ]

    params_expected = [
        "service",
        "request",
        "version",
        "identifier",
    ]

    resource_types_permissions = {
        models.Process: models.Process.permissions
    }

    def resource_requested(self):
        # type: () -> Optional[Tuple[ServiceOrResourceType, bool]]
        wps_request = self.permission_requested()
        if wps_request == Permission.GET_CAPABILITIES:
            return self.service, True
        if wps_request in [Permission.DESCRIBE_PROCESS, Permission.EXECUTE]:
            wps_id = self.service.resource_id
            proc_id = self.parser.params["identifier"]
            if not proc_id:
                return self.service, False
            session = get_connected_session(self.request)
            proc = models.find_children_by_name(proc_id, parent_id=wps_id, db_session=session)
            if proc:
                return proc, True
            return self.service, False
        LOGGER.debug("Unknown WPS operation for permission: %s", wps_request)
        return None


class ServiceBaseWMS(ServiceOWS):
    """
    Service that represents basic capabilities of a ``Web Map Service`` endpoint.

    .. seealso::
        https://www.ogc.org/standards/wms (OpenGIS WMS 1.3.0 implementation)
    """

    @abc.abstractmethod
    def resource_requested(self):
        raise NotImplementedError

    # base implementation only provides the following requests
    permissions = [
        Permission.GET_CAPABILITIES,
        Permission.GET_MAP,
        Permission.GET_FEATURE_INFO,
    ]

    params_expected = [
        "service",
        "request",
        "version",
        "layers",
        "layername",
        "dataset"
    ]


class ServiceNCWMS2(ServiceBaseWMS):
    """
    Service that represents a ``Web Map Service`` endpoint with functionalities specific to ``ncWMS2`` .

    .. seealso::
        https://reading-escience-centre.gitbooks.io/ncwms-user-guide/content/04-usage.html
    """
    service_base = "wms"
    service_type = "ncwms"

    permissions = [
        Permission.GET_CAPABILITIES,
        Permission.GET_MAP,
        Permission.GET_FEATURE_INFO,
        # ncWMS specific extensions
        Permission.GET_LEGEND_GRAPHIC,
        Permission.GET_METADATA,
        # FIXME: not implemented
        # Permission.GET_TIMESERIES,
        # Permission.GET_VERTICAL_PROFILE,
        # Permission.GET_VERTICAL_TRANSECT,
    ]

    resource_types_permissions = {
        models.File: [
            Permission.GET_CAPABILITIES,
            Permission.GET_MAP,
            Permission.GET_FEATURE_INFO,
            Permission.GET_LEGEND_GRAPHIC,
            Permission.GET_METADATA,
        ],
        models.Directory: [
            Permission.GET_CAPABILITIES,
            Permission.GET_MAP,
            Permission.GET_FEATURE_INFO,
            Permission.GET_LEGEND_GRAPHIC,
            Permission.GET_METADATA,
        ]
    }

    def resource_requested(self):
        # type: () -> Optional[Tuple[ServiceOrResourceType, bool]]
        # According to the permission, the resource we want to authorize is not formatted the same way
        permission_requested = self.permission_requested()
        netcdf_file = None
        if permission_requested == Permission.GET_CAPABILITIES:
            # https://colibri.crim.ca/twitcher/ows/proxy/ncWMS2/wms?SERVICE=WMS&REQUEST=GetCapabilities&
            #   VERSION=1.3.0&DATASET=outputs/ouranos/subdaily/aet/pcp/aet_pcp_1961.nc
            if "dataset" in self.parser.params:
                netcdf_file = self.parser.params["dataset"]

        elif permission_requested == Permission.GET_MAP:
            # https://colibri.crim.ca/ncWMS2/wms?SERVICE=WMS&VERSION=1.3.0&REQUEST=GetMap&FORMAT=image%2Fpng&
            #   TRANSPARENT=TRUE&ABOVEMAXCOLOR=extend&STYLES=default-scalar%2Fseq-Blues&
            #   LAYERS=outputs/ouranos/subdaily/aet/pcp/aet_pcp_1961.nc/PCP&EPSG=4326
            netcdf_file = self.parser.params["layers"]
            if netcdf_file:
                netcdf_file = netcdf_file.rsplit("/", 1)[0]

        elif permission_requested == Permission.GET_METADATA:
            # https://colibri.crim.ca/ncWMS2/wms?request=GetMetadata&item=layerDetails&
            #   layerName=outputs/ouranos/subdaily/aet/pcp/aet_pcp_1961.nc/PCP
            netcdf_file = self.parser.params["layername"]
            if netcdf_file:
                netcdf_file = netcdf_file.rsplit("/", 1)[0]

        else:
            return self.service, False

        found_child = self.service
        target = False
        if netcdf_file:
            if "output/" not in netcdf_file:
                return self.service, False
            # FIXME: this is probably too specific to birdhouse... leave as is for bw-compat, adjust as needed
            netcdf_file = netcdf_file.replace("outputs/", "birdhouse/")

            db_session = get_connected_session(self.request)
            file_parts = netcdf_file.split("/")
            while found_child and file_parts:
                part = file_parts.pop(0)
                res_id = found_child.resource_id
                found_child = models.find_children_by_name(part, parent_id=res_id, db_session=db_session)
            # target resource reached if no more parts to process, otherwise we have some parent (minimally the service)
            target = not len(file_parts)
        return found_child, target


class ServiceGeoserverBase(ServiceOWS):
    """
    Provides basic configuration parameters and functionalities shared by `Geoserver` implementations.
    """

    @classmethod
    @classproperty
    @abc.abstractmethod
    def resource_scoped(cls):
        # type: () -> bool
        """
        Indicates if the :term:`Service` is allowed to employ scoped :class:`models.Workspace` naming.

        When allowed, the :class:`models.Workspace` can be inferred from the request parameter
        defined by :attr:`resource_param` to retrieve scoped name as ``<WORKSPACE>:<RESOURCE>``.
        When not allowed, the resource name is left untouched and `Magpie` will not attempt to infer
        any :class:`models.Workspace` from it. In that case, :class:`models.Workspace` can only be specified
        in the request path for isolated :term:`Resource` references.

        .. note::
            When this parameter is ``False`` for a given :term:`Service` implementation, children
            :term:`Resources <Resource>` can still be named in a similar ``<namespace>:<element>`` fashion.
            The only distinction is that the **full** :term:`Resource` should include this complete definition
            instead of nesting ``<namespace>`` and ``<element>`` into two distinct :term:`Resources <Resource>`.
        """
        raise NotImplementedError

    @classproperty
    @abc.abstractmethod
    def resource_multi(cls):  # noqa
        # type: () -> bool
        """
        Indicates if the :term:`Service` supports multiple simultaneous :term:`Resource` references.

        When supported, the value retrieved from :attr:`resource_param` can be comma-separated to represent
        multiple :term:`Resource` of the same nature, which can all be retrieved with the same request.
        Otherwise, single value only is considered by default.

        .. note::
            Permission modifier :data:`Access.ALLOW` will have to be resolved for all those :term:`Resource`
            references for the request to be granted access.
        """
        raise NotImplementedError

    @classproperty
    @abc.abstractmethod
    def resource_param(cls):  # noqa
        # type: () -> Union[Str, List[Str]]
        """
        Name of the request query parameter(s) to access requested leaf children resource.

        If a single string is defined, the parameter must be equal to this value (case insensitive).
        When using a list, any specified name combination will be resolved as the same parameter.

        .. note::
            The resulting parameter(s) are automatically added to :meth:`params_expected` to ensure they are always
            retrieved in the :attr:`parser` from the request query parameters.

        .. seealso::
            :meth:`resource_param_requested` to obtain the resolved parameter considering any applicable combination.
        """
        raise NotImplementedError

    @classproperty
    @abc.abstractmethod
    def resource_types_permissions(cls):  # noqa
        # type: () -> ResourceTypePermissions
        """
        Explicit permissions provided for resources for a given :term:`OWS` implementation.
        """
        raise NotImplementedError

    @classproperty
    def params_expected(cls):  # noqa
        # type: () -> List[Str]
        """
        Specify typical `Geoserver` request query parameters expected for any sub-service implementation.

        The :attr:`resource_param` is also added to ensure it is always parsed based on the derived implementation.
        """
        if isinstance(cls.resource_param, six.string_types):
            impl_params = [cls.resource_param]
        elif isinstance(cls.resource_param, list):
            impl_params = cls.resource_param
        else:
            name = fully_qualified_name(cls)
            raise NotImplementedError(f"Missing or invalid definition of 'resource_param' in service: {name}")
        base_params = [
            "request",
            "service",
            "version",
        ]
        return base_params + impl_params

    def resource_param_requested(self):
        # type: () -> List[Str]
        """
        Obtain the resolved value(s) of the resource query parameter from :term:`OWS` parser applied onto the request.
        """
        if isinstance(self.resource_param, six.string_types):
            value = self.parser.params[self.resource_param]
            if self.resource_multi and isinstance(value, six.string_types):
                return value.split(",")
            return [value]
        if isinstance(self.resource_param, list):
            values = []
            for param in self.resource_param:
                value = self.parser.params[param]
                if self.resource_multi and isinstance(value, six.string_types):
                    values.extend(value.split(","))
                else:
                    values.append(value)
            return values
        name = fully_qualified_name(self)
        raise NotImplementedError(f"Missing or invalid requested 'resource_param' in service: {name}")

    def resource_requested(self):
        # type: () -> MultiResourceRequested
        """
        Parse the requested resource down to the applicable :class:`models.Workspace`.

        .. note::
            Further child resource processing must be accomplished by the derived implementation as needed.
        """
        path_parts = self._get_request_path_parts()
        if not path_parts:
            return self.service, False
        permission = self.permission_requested()
        parts_lower = [part.lower() for part in path_parts]
        if parts_lower and parts_lower[0] == "":
            path_parts = path_parts[1:]
            parts_lower = parts_lower[1:]
        if parts_lower and parts_lower[0] == "geoserver":
            path_parts = path_parts[1:]
            parts_lower = parts_lower[1:]
        workspace_name = None
        if len(parts_lower) > 1 and parts_lower[1] == self.service_base:
            workspace_name = path_parts[0]
        if permission == Permission.GET_CAPABILITIES:
            # here we need to check the workspace in the path
            #   /geoserver/<OWS>?request=getcapabilities (get all workspaces)
            #   /geoserver/<WORKSPACE>/<OWS>?request=getcapabilities (only for the workspace in the path)
            if (
                not path_parts or
                self.service_base not in parts_lower or
                (len(parts_lower) == 1 and parts_lower[0] == self.service_base)
            ):
                return self.service, True
            return self.service, False

        # following requests lead to the same resolution, need to check the workspace in the layer
        #   /geoserver/<WORKSPACE>/<OWS>?<RESOURCE_PARAM>=[<WORKSPACE>:]<LAYER_NAME>&request=<PERMISSION>
        #   /geoserver/<OWS>?<RESOURCE_PARAM>=<WORKSPACE>:<LAYER_NAME>&request=<PERMISSION>
        matched_resources = []
        session = get_connected_session(self.request)
        for res_name in self.resource_param_requested():
            if not res_name:
                continue
            workspace_isolated = None  # reset for next layer

            # if missing, consider layer name as not scoped under workspace
            if self.resource_scoped and ":" in res_name:
                workspace_scope, res_name = res_name.rsplit(":", 1)
                if not workspace_name:
                    # workspace only in scoped layer parameter
                    workspace_isolated = workspace_scope
                elif workspace_name != workspace_scope:
                    # In case the request was formed with both workspace in path and scoped resource name,
                    # consider the workspace as not resolved since we cannot know which one to target.
                    # This avoids erroneously granting access to restricted layer from another workspace by
                    # forging a request that would include some workspace for which the user does have access.
                    return [(self.service, False)]
                else:
                    # workspace only in path, layer not scoped
                    workspace_isolated = workspace_name

            # never split if service doesn't support resource scoping
            # therefore, workspace can only be provided by path
            # do the same if scoping is supported but no scope was specified (directly the resource in param)
            elif not self.resource_scoped or ":" not in res_name:
                workspace_isolated = workspace_name

            if not workspace_isolated:
                continue
            workspace = models.find_children_by_name(child_name=workspace_isolated,
                                                     parent_id=self.service.resource_id,
                                                     db_session=session)
            if workspace:
                if not res_name:
                    matched_resources.append((workspace, False))
                    continue
                resource = models.find_children_by_name(child_name=res_name,
                                                        parent_id=workspace.resource_id,
                                                        db_session=session)
                if resource:
                    matched_resources.append((resource, True))
                else:
                    matched_resources.append((workspace, False))
                continue
            matched_resources.append((self.service, False))

        # if no children resource where matched, check if the Workspace was provided in the path
        # in such case, a match would provide a closer resource scope, but assume its not a match
        # since other operation than already handled 'GetCapabilities' all involve resources under Workspace
        if not matched_resources and workspace_name:
            workspace = models.find_children_by_name(child_name=workspace_name,
                                                     parent_id=self.service.resource_id,
                                                     db_session=session)
            if workspace:
                return [(workspace, False)]
        if not matched_resources:
            return [(self.service, False)]
        return matched_resources


class ServiceGeoserverWMS(ServiceGeoserverBase, ServiceBaseWMS):  # order important to call overridden class properties
    """
    Service that represents a ``Web Map Service`` endpoint with functionalities specific to ``GeoServer``.

    .. seealso::
        https://docs.geoserver.org/latest/en/user/services/wms/reference.html
    """
    service_base = "wms"
    service_type = "geoserverwms"

    resource_scoped = True
    resource_multi = True  # can stack layers on map
    resource_param = "layers"

    permissions = [
        Permission.GET_CAPABILITIES,
        Permission.GET_MAP,
        Permission.GET_FEATURE_INFO,
        # GeoServer specific extensions
        Permission.GET_LEGEND_GRAPHIC,
        Permission.DESCRIBE_LAYER,
        # FIXME: not implemented
        # Permission.EXCEPTIONS,
    ]

    # only workspace directly followed by layers
    child_structure_allowed = {
        models.Service: [models.Workspace],
        models.Workspace: [models.Layer],
        models.Layer: [],
    }

    resource_types_permissions = {
        models.Workspace: permissions,
        models.Layer: permissions,
    }


class ServiceAccess(ServiceInterface):
    service_type = "access"

    permissions = [Permission.ACCESS]

    resource_types_permissions = {}

    def resource_requested(self):
        # type: () -> TargetResourceRequested
        return self.service, True

    def permission_requested(self):
        # type: () -> PermissionRequested
        return Permission.ACCESS


class ServiceAPI(ServiceInterface):
    """
    Service that provides resources per individual request path segments.
    """
    service_type = "api"

    permissions = models.Route.permissions

    resource_types_permissions = {
        models.Route: models.Route.permissions
    }

    child_structure_allowed = {
        models.Service: [models.Route],
        models.Route: [models.Route],
    }

    def resource_requested(self):
        # type: () -> TargetResourceRequested
        route_parts = self._get_request_path_parts()
        if not route_parts:
            return self.service, True
        route_found = route_child = self.service

        # find deepest possible resource matching sub-route name
        while route_child and route_parts:
            part_name = route_parts.pop(0)
            route_res_id = route_child.resource_id
            session = get_connected_session(self.request)
            route_child = models.find_children_by_name(part_name, parent_id=route_res_id, db_session=session)
            if route_child:
                route_found = route_child

        # target reached if no more parts to process, otherwise we have some parent (minimally the service)
        route_target = not len(route_parts) and route_child is not None
        return route_found, route_target

    def permission_requested(self):
        # type: () -> PermissionRequested
        if self.request.method.upper() in ["GET", "HEAD"]:
            return Permission.READ
        return Permission.WRITE


class ServiceWFS(ServiceOWS):
    """
    Service that represents a ``Web Feature Service`` endpoint.

    .. seealso::
        https://www.ogc.org/standards/wfs (OpenGIS WFS 2.0.0 implementation)
    """
    service_base = "wfs"
    service_type = "wfs"

    permissions = [
        # v1.0.0
        Permission.GET_CAPABILITIES,
        Permission.GET_FEATURE,
        Permission.DESCRIBE_FEATURE_TYPE,
        Permission.LOCK_FEATURE,
        Permission.TRANSACTION,
        # v2.0.0 only
        Permission.GET_FEATURE_WITH_LOCK,
        Permission.CREATE_STORED_QUERY,
        Permission.DROP_STORED_QUERY,
        Permission.LIST_STORED_QUERIES,
        Permission.DESCRIBE_STORED_QUERIES,
    ]

    params_expected = [
        "service",
        "request",
        "version",
        "typenames"
    ]

    resource_types_permissions = {
        # note: basic WFS does not implement Workspace
        models.Layer: models.Layer.permissions
    }

    def resource_requested(self):
        # type: () -> TargetResourceRequested
        if not self.parser.params["typenames"]:
            return self.service, False
        names = self.parser.params["typenames"]  # can be comma-separated or single layer
        layer = names.split(",")
        if layer:
            # FIXME: multi-resource not supported, must update effective permissions handling
            if len(layer) > 1:
                LOGGER.warning("Multiple WFS layers access not implemented, considering access using parent workspace.")
                return self.service, False
            layer = layer[0]
            session = get_connected_session(self.request)
            layer_res = models.find_children_by_name(child_name=layer,
                                                     parent_id=self.service.resource_id,
                                                     db_session=session)
            if layer_res is not None:
                return layer_res, True
            return self.service, False
        return self.service, True   # no children resource, so can only be the service


class ServiceGeoserverWFS(ServiceGeoserverBase, ServiceWFS):  # order important to call overridden class properties
    """
    Service that represents a ``Web Feature Service`` endpoint with functionalities specific to ``GeoServer``.

    .. seealso::
        https://docs.geoserver.org/latest/en/user/services/wfs/reference.html
    """
    service_base = "wfs"
    service_type = "geoserverwfs"

    resource_scoped = True
    resource_multi = True
    resource_param = ["typenames", "typename"]  # replacement between WPS 1.x/2.x often handled as synonyms

    permissions = ServiceWFS.permissions + [
        # v1.1.0 only
        Permission.GET_GML_OBJECT,
        # v2.0.0 only
        Permission.GET_PROPERTY_VALUE
    ]

    resource_types_permissions = {
        models.Workspace: permissions,
        models.Layer: permissions,
    }

    # only workspace directly followed by layers
    child_structure_allowed = {
        models.Service: [models.Workspace],
        models.Workspace: [models.Layer],
        models.Layer: [],
    }


class ServiceTHREDDS(ServiceInterface):
    """
    Service that represents a ``THREDDS Data Server`` endpoint.
    """
    service_type = "thredds"

    permissions = [
        Permission.BROWSE,  # for metadata access
        Permission.READ,    # for file data access
        Permission.WRITE,   # NOTE: see special usage of WRITE in docs
    ]

    resource_types_permissions = {
        models.Directory: permissions,
        models.File: permissions,
    }

    child_structure_allowed = {
        models.Service: [models.Directory, models.File],
        models.Directory: [models.Directory, models.File],
        models.File: [],
    }

    configurable = True

    def get_config(self):
        # type: () -> ServiceConfiguration
        if self._config is not None:
            return self._config
        self._config = super(ServiceTHREDDS, self).get_config() or {}
        self._config.setdefault("skip_prefix", "thredds")
        self._config.setdefault("file_patterns", [".*\\.nc"])
        self._config.setdefault("data_type", {"prefixes": []})
        if not self._config["data_type"]["prefixes"]:
            self._config["data_type"]["prefixes"] = ["fileServer", "dodsC", "dap4", "wcs", "wms"]
        self._config.setdefault("metadata_type", {"prefixes": []})
        if not self._config["metadata_type"]["prefixes"]:
            self._config["metadata_type"]["prefixes"] = [None, "catalog\\.\\w+", "catalog", "ncml", "uddc", "iso"]
        return self._config

    def get_path_parts(self):
        # type: () -> Optional[List[Str]]
        cfg = self.get_config()
        path_parts = self._get_request_path_parts()
        skip_prefix = cfg["skip_prefix"]
        if path_parts and skip_prefix:
            full_path = "/".join(path_parts)
            skip_prefix = skip_prefix.lstrip("/").rstrip("/")
            if full_path.startswith(skip_prefix):
                path_parts = full_path.split(skip_prefix)[-1].split("/")
                return path_parts[1:]  # remove extra '' added by split
        return path_parts

    @staticmethod
    def is_match(value, pattern):
        # type: (Str, Str) -> Optional[Str]
        try:
            match = re.match(pattern, value)
            if match is None:
                return None
            return match.group(0)  # use this method for backward support py35 not supporting [] access
        except (TypeError, KeyError):  # fail match or fail to extract (depending on configured pattern)
            return None

    def resource_requested(self):
        # type: () -> TargetResourceRequested
        path_parts = self.get_path_parts()

        # handle optional prefix as targeting the service directly
        if not path_parts or len(path_parts) < 2:
            return self.service, True
        path_parts = path_parts[1:]
        cfg = self.get_config()

        # find deepest possible resource matching either Directory or File by name
        found_resource = child_resource = self.service
        while child_resource and path_parts:
            part_name = path_parts.pop(0)
            # when reaching the final part, test for possible file pattern, otherwise default to literal value
            #   allows combining different naming formats into a common file resource (eg: extra extensions)
            # if final part is a directory, still works because of literal value
            #   directory name must match exactly, no format naming variants allowed
            # if final part is 'catalog.html' file, lookup would fail and fall back to previous directory part
            #   since that would be the last part extracted, the parent directory will be matched as intended
            if not path_parts:
                for pattern in cfg["file_patterns"]:
                    matched = self.is_match(part_name, pattern)
                    if matched is not None:
                        part_name = matched
                        break
            session = get_connected_session(self.request)
            child_res_id = child_resource.resource_id
            child_resource = models.find_children_by_name(part_name, parent_id=child_res_id, db_session=session)
            if child_resource:
                found_resource = child_resource

        # target resource reached if no more parts to process, otherwise we have some parent (minimally the service)
        target = not len(path_parts) and child_resource is not None
        return found_resource, target

    def permission_requested(self):
        # type: () -> PermissionRequested
        cfg = self.get_config()
        path_parts = self.get_path_parts()
        path_prefix = None  # in case of no `<prefix>`, simulate as `null`
        if path_parts:
            path_prefix = path_parts[0]
        for prefixes, permission in [
            (cfg["metadata_type"]["prefixes"], Permission.BROWSE),  # first to favor BROWSE over READ prefix conflicts
            (cfg["data_type"]["prefixes"], Permission.READ),
        ]:
            for pattern_prefix in prefixes:  # type: Str
                if path_prefix is None and pattern_prefix is None:
                    return permission
                if self.is_match(path_prefix, pattern_prefix) is not None:
                    return permission
        return None  # automatically deny


class ServiceGeoserverWPS(ServiceGeoserverBase, ServiceWPS):  # order important to call overridden class properties
    """
    Service that represents a ``Web Processing Service`` under a `Geoserver` instance.
    """
    service_type = "geoserverwps"

    resource_scoped = False  # name in 'identifier' must not be split and does not match WORKSPACE
    resource_multi = True  # possible to describe multiple processes at the same time
    resource_param = "identifier"

    resource_types_permissions = {
        models.Workspace: ServiceWPS.permissions,
        models.Process: models.Process.permissions,
    }

    # only workspace directly followed by layers
    child_structure_allowed = {
        models.Service: [models.Workspace],
        models.Workspace: [models.Process],
        models.Layer: [],
    }


class ServiceGeoserver(ServiceGeoserverBase):
    """
    Service that encapsulates the multiple :term:`OWS` endpoints from `GeoServer` services.

    .. seealso::
        https://docs.geoserver.org/stable/en/user/services/index.html
    """
    service_base = None  # use 'service_map' and 'service_ows'
    service_type = "geoserver"
    service_map = {
        ServiceGeoserverWFS.service_base: ServiceGeoserverWFS,
        ServiceGeoserverWMS.service_base: ServiceGeoserverWMS,
        ServiceGeoserverWPS.service_base: ServiceGeoserverWPS,
    }

    @classproperty
    def service_ows_supported(cls):  # noqa
        # type: () -> Set[Type[ServiceOWS]]
        return set(cls.service_map.values())

    # only allow workspace directly under service
    # then, only layer or process under that workspace
    child_structure_allowed = {
        models.Service: [models.Workspace],
        models.Workspace: [models.Layer, models.Process],
        models.Layer: [],
        models.Process: [],
    }
    """
    Allowed children resource structure for `Geoserver`.

    .. note::
        In the context of `Geoserver`, `WPS` are applied on available resources (`WFS`, `WMS`, etc.).
        For this reason, the :class:`models.Process` also needs to be scoped under :class:`models.Workspace` in order
        to grant access to those resources to work on them, but the :class:`models.Workspace` name **MUST** be in the
        path (i.e.: ``identifier=<WORKSPACE>:<PROCESS_ID>`` request parameter does not work).
        Without the :class:`models.Workspace` scope in the path, ``identifier`` parameter fails to be resolved by
        `Geoserver`, as if it was unspecified. Attribute :attr:`ServiceGeoserverWPS.resource_scoped` controls the
        behaviour of splitting the defined :attr:`resource_param` into :class:`models.Workspace` and child components.
    """

    configurable = True

    def get_config(self):
        # type: () -> ServiceConfiguration
        """
        Obtain the configuration defining which :term:`OWS` services are enabled under this instance.

        Should provide a mapping of all :term:`OWS` service type names to enabled boolean status.
        """
        if self._config is not None:
            return self._config
        self._config = super(ServiceGeoserver, self).get_config() or {}
        for svc_type in type(self).service_map:
            self._config.setdefault(svc_type, True)
            if not isinstance(self._config[svc_type], bool):
                self._config[svc_type] = True
        self._config = {key: self._config[key] for key in sorted(self._config)}
        return self._config

    @classproperty
    def params_expected(cls):  # noqa
        # type: () -> List[Str]
        params = set()
        for svc in cls.service_ows_supported:
            if issubclass(svc, ServiceOWS):
                param_names = getattr(svc, "params_expected", None)
                if param_names:
                    params.update(param_names)
        return list(params)

    @classproperty
    def permissions(cls):  # noqa
        # type: () -> List[Permission]
        perms = set()
        for svc in cls.service_ows_supported:
            if issubclass(svc, ServiceOWS):
                svc_perms = getattr(svc, "permissions", None)
                if svc_perms:
                    perms.update(svc.permissions)
        return list(perms)

    @classproperty
    def resource_types_permissions(cls):  # noqa
        # type: () -> ResourceTypePermissions
        perms = {}  # type: ResourceTypePermissions
        for svc in cls.service_ows_supported:
            if issubclass(svc, ServiceOWS):
                svc_res_perms = getattr(svc, "resource_types_permissions", None)
                if svc_res_perms:
                    for res_type, res_perms in svc_res_perms.items():
                        if res_type in perms:
                            perms[res_type] = list(set(perms[res_type]) | set(res_perms))
                        else:
                            perms[res_type] = list(res_perms)
        return perms

    def __init__(self, service, request):
        # type: (models.Service, Optional[Request]) -> None
        self._service_requested = None  # cache computed requested service to avoid loop for each property
        super(ServiceGeoserver, self).__init__(service, request)

    def _set_request(self, request):
        # type: (Request) -> None
        self._service_requested = None  # reset to make sure any path change finds the new applicable service
        super(ServiceGeoserver, self)._set_request(request)

    def service_requested(self):
        # type: () -> Optional[Type[ServiceGeoserverBase]]
        """
        Obtain the applicable :term:`OWS` implementation according to parsed request parameters.
        """
        if self._service_requested:
            return self._service_requested
        # guaranteed to exist and lowercase string if provided, otherwise None
        svc = self.parser.params["service"]
        req = self.parser.params["request"]
        if not svc and req:
            # geoserver allows omitting 'service' request query parameter because it can be inferred from the path
            # since all OWS services are accessed using '/geoserver/<SERVICE>?request=...'
            # attempt to match using applicable path fragment
            svc_path = self.request.path.rsplit("/", 1)[-1].lower()
            for svc_ows in type(self).service_ows_supported:
                if svc_path == svc_ows.service_base:
                    svc = svc_ows.service_base
                    break
        config = self.get_config()
        if svc not in config or not config[svc]:
            self._service_requested = None
            return None
        self._service_requested = type(self).service_map[svc]
        return self._service_requested

    @classproperty
    def resource_scoped(cls):  # noqa
        # type: () -> bool
        svc = cls.service_requested()
        return svc.resource_scoped if svc else False

    @classproperty
    def resource_multi(cls):  # noqa
        # type: () -> bool
        svc = cls.service_requested()
        return svc.resource_multi if svc else False

    @classproperty
    def resource_param(cls):  # noqa
        # type: () -> Union[Str, List[Str]]
        svc = cls.service_requested()
        return cls.resource_param if svc else []

    def resource_requested(self):
        # type: () -> MultiResourceRequested
        svc = self.service_requested()
        if not svc:
            return None
        return svc(self.service, self.request).resource_requested()

    def permission_requested(self):
        # type: () -> PermissionRequested
        svc = self.service_requested()
        if not svc:
            return None
        return svc(self.service, self.request).permission_requested()


SERVICE_TYPES = frozenset([
    ServiceAccess,
    ServiceAPI,
    ServiceGeoserver,
    ServiceGeoserverWFS,
    ServiceGeoserverWMS,
    ServiceGeoserverWPS,
    ServiceNCWMS2,
    ServiceTHREDDS,
    ServiceWFS,
    ServiceWPS
])
SERVICE_TYPE_DICT = dict()
for _svc in SERVICE_TYPES:
    if _svc.service_type in SERVICE_TYPE_DICT:
        raise KeyError("Duplicate resource type identifiers not allowed")
    SERVICE_TYPE_DICT[_svc.service_type] = _svc


def service_factory(service, request):
    # type: (models.Service, Request) -> ServiceInterface
    """
    Retrieve the specific service class from the provided database service entry.
    """
    ax.verify_param(service, param_compare=models.Service, is_type=True,
                    http_error=HTTPBadRequest, content={"service": repr(service)},
                    msg_on_fail="Cannot process invalid service object.")
    service_type = ax.evaluate_call(lambda: service.type, http_error=HTTPInternalServerError,
                                    msg_on_fail="Cannot retrieve service type from object.")
    ax.verify_param(service_type, is_in=True, param_compare=SERVICE_TYPE_DICT.keys(),
                    http_error=HTTPNotImplemented, content={"service_type": service_type},
                    msg_on_fail="Undefined service type mapping to service object.")

    def _make_service(_typ, _svc, _req):
        # type: (Str, models.Service, Request) -> ServiceInterface
        try:
            return SERVICE_TYPE_DICT[_typ](_svc, _req)
        except Exception as exc:
            LOGGER.debug("Failed service creation using (type [%s], service [%s], request [%s]). Exception: [%s] (%s).",
                         _typ, _svc, _req, type(exc).__name__, exc, exc_info=exc)
            raise

    return ax.evaluate_call(lambda: _make_service(service_type, service, request),
                            http_error=HTTPInternalServerError, content={"service_type": service_type},
                            msg_on_fail="Failed to find requested service type.")


def get_resource_child_allowed(resource):
    # type: (ServiceOrResourceType) -> bool
    """
    Verifies if the specified resource allows nesting children resources under it considering its specific type.

    Makes sure to obtain the specific :class:`Service` or :class:`Resource` implementation to verify children support.
    If this is not accomplished, the default attribute of base :class:`Service` or :class:`Resource` would erroneously
    indicate that children are allowed.

    :param resource: Item for which to verify if children resources are allowed.
    :return: Whether the resource can nest more resources or not.
    """
    if resource.resource_type_name == models.Service.resource_type_name:
        res_impl = SERVICE_TYPE_DICT[resource.type]
    else:
        res_impl = models.RESOURCE_TYPE_DICT[resource.resource_type_name]
    return res_impl.child_resource_allowed


def invalidate_service(service_name):
    # type: (Str) -> None
    """
    Invalidates any caching reference to the specified service name.
    """
    # pylint: disable=W0212,protected-access
    try:
        # could fail if twitcher was not installed
        from magpie.adapter.magpieowssecurity import MagpieOWSSecurity  # noqa
        from magpie.adapter.magpieservice import MagpieServiceStore  # noqa

        if "service" in cache_regions:
            region_invalidate(MagpieOWSSecurity._get_service_cached, "service", service_name)  # noqa
            region_invalidate(MagpieServiceStore._fetch_by_name_cached, "service", service_name)  # noqa
    except ImportError:
        LOGGER.warning("Could not invalidate cache of service: [%s]", service_name)

    if "acl" in cache_regions:
        for namespace in [ServiceInterface._get_acl_cached]:
            cache_keys = (service_name, )  # full signature: (service_name, request_method, request_path, user_id)
            region_invalidate(namespace, "acl", *cache_keys)  # noqa
            # beaker doesn't provide a direct method to invalidate partial key.
            # Therefore, do 'region_invalidate' equivalent operations manually.
            #   If above 'region_invalidate' did not raise cache-key error,
            #   it is safe to simplify most steps without pre-checks.
            region = cache_regions["acl"]
            ns_key = getattr(namespace, "_arg_namespace")
            cache = Cache._get_cache(ns_key, region)
            # keys are normally generated by concatenating byte-str repr of all params received as input
            # we care only about service-name in this case
            service_param_key = (service_name + " ").encode("ascii", "backslashreplace")
            for func_params_key in list(cache.namespace.dictionary):
                if func_params_key.startswith(service_param_key):
                    cache.namespace.dictionary.pop(func_params_key, None)
