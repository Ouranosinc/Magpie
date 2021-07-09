import abc
import re
from typing import TYPE_CHECKING

import six
from beaker.cache import cache_region, cache_regions, region_invalidate
from pyramid.httpexceptions import HTTPBadRequest, HTTPInternalServerError, HTTPNotImplemented
from pyramid.security import ALL_PERMISSIONS, DENY_ALL
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.permissions import permission_to_pyramid_acls

from magpie import models
from magpie.api import exception as ax
from magpie.constants import get_constant
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
from magpie.utils import get_logger

LOGGER = get_logger(__name__)
if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Collection, Dict, List, Optional, Set, Tuple, Type, Union

    from pyramid.request import Request

    from magpie.typedefs import AccessControlListType, ServiceConfiguration, ServiceOrResourceType, Str


class ServiceMeta(type):
    @property
    def resource_types(cls):
        # type: (Type[ServiceInterface]) -> List[models.Resource]
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
        return len(cls.resource_types) > 0


@six.add_metaclass(ServiceMeta)
class ServiceInterface(object):
    # required service type identifier (unique)
    service_type = None                 # type: Str
    # required request parameters for the service
    params_expected = []                # type: List[Str]
    # global permissions allowed for the service (top-level resource)
    permissions = []                    # type: List[Permission]
    # dict of list for each corresponding allowed resource permissions (children resources)
    resource_types_permissions = {}     # type: Dict[models.Resource, List[Permission]]

    def __init__(self, service, request):
        # type: (models.Service, Request) -> None
        self.service = service          # type: models.Service
        self.request = request          # type: Request

    @abc.abstractmethod
    def permission_requested(self):
        # type: () -> Optional[Union[Permission, Collection[Permission]]]
        """
        Defines how to interpret the incoming request into :class:`Permission` definitions for the given service.

        Each service must implement its own definition.
        The method must specifically define how to convert generic request path, query, etc. elements into permissions
        that match the service and its children resources.

        If ``None`` is returned, the :term:`ACL` will effectively be resolved to denied access.
        Otherwise, one or more returned :class:`Permission` will indicate which permissions should be looked for to
        resolve the :term:`ACL` of the authenticated user and its groups.
        """
        raise NotImplementedError("missing implementation of request permission converter")

    @abc.abstractmethod
    def resource_requested(self):
        # type: () -> Optional[Tuple[ServiceOrResourceType, bool]]
        """
        Defines how to interpret the incoming request into the targeted :class:`model.Resource` for the given service.

        Each service must implement its own definition.

        The expected return value must be either of the following::

            - (target-resource, True)     when the exact resource is found
            - (parent-resource, False)    when any parent of the resource is found
            - None                        when invalid request or not found resource

        The `parent-resource` indicates the *closest* higher-level resource in the hierarchy that would nest the
        otherwise desired `target-resource`. The idea behind this is that `Magpie` will be able to resolve the effective
        recursive permission even if not all corresponding resources were explicitly defined in the database.

        For example, if the request *would* be interpreted with the following hierarchy after service-specific
        resolution::

            ServiceA
                Resource1         <== closest *existing* parent resource
                    [Resource2]   <== target (according to service/request resolution), but not existing in database

        A permission defined as Allow/Recursive on ``Resource1`` should normally allow access to ``Resource2``. If
        ``Resource2`` is not present in the database though, it cannot be looked for, and the corresponding ACL cannot
        be generated. Because the (real) protected service using `Magpie` can have a large and dynamic hierarchy, it
        is not convenient to enforce perpetual sync between it and its resource representation in `Magpie`. Using the
        ``(parent-resource, False)`` will allow resolution of permission from the closest available parent.

        .. note::
            In case of `parent-resource` returned, only `recursive`-scoped permissions will be considered, since the
            missing `target-resource` is the only one that should be checked for `match`-scoped permissions. For this
            reason, the service-specific implementation should preferably return the explicit `target` resource whenever
            possible.

        If the returned resource is ``None``, the ACL will effectively be resolved to denied access. This can be used
        to indicate failure to retrieve the expected resource or that corresponding resource does not exist. Otherwise,
        this method implementation should convert any request path, query parameters, etc. into an existing resource.

        :returns: tuple of reference resource (target/parent), and enabled status of match permissions (True/False)
        """
        raise NotImplementedError

    def user_requested(self):
        user = self.request.user
        if not user:
            anonymous = get_constant("MAGPIE_ANONYMOUS_USER", self.request)
            user = UserService.by_user_name(anonymous, db_session=self.request.db)
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
        if self.request.headers.get("Cache-Control") == "no-cache":
            region_invalidate(self._get_acl_cached, "acl", *cache_keys)
        return self._get_acl_cached(*cache_keys)

    @cache_region("acl")
    def _get_acl_cached(self, service_name, request_method, request_path, user_id):  # noqa: F811
        # type: (Str, Str, Str, Optional[int]) -> AccessControlListType
        """
        Cache this method with :py:mod:`beaker` based on the provided caching key parameters.

        If the cache is not hit (expired timeout or new key entry), calls :meth:`ServiceInterface.get_acl` to retrieve
        effective permissions of the requested resource and specific permission for the applicable service and user
        executing the request.

        .. note::
            Function arguments are required to generate caching keys by which cached elements will be retrieved.
            Actual arguments are not needed as we employ stored objects in the instance.

        .. seealso::
            - :meth:`ServiceInterface.permission_requested`
            - :meth:`ServiceInterface.resource_requested`
            - :meth:`ServiceInterface.user_requested`
        """
        permissions = self.permission_requested()
        if permissions is None:
            return [DENY_ALL]
        resource = self.resource_requested()
        if not resource:
            return [DENY_ALL]
        if not isinstance(resource, tuple):
            is_target = False
        else:
            resource, is_target = resource
        if not isinstance(permissions, (list, set, tuple)):
            permissions = {permissions}
        user = self.user_requested()
        return self._get_acl(user, resource, permissions, allow_match=is_target)

    def _get_acl(self, user, resource, permissions, allow_match=True):
        # type: (models.User, ServiceOrResourceType, Collection[Permission], bool) -> AccessControlListType
        """
        Resolves the resource-tree and the user/group inherited permissions into a simplified ACL for this resource.

        .. seealso::
            - :meth:`effective_permissions`
        """
        permissions = self.effective_permissions(user, resource, permissions, allow_match)
        return [perm.ace(self.request.user) for perm in permissions]

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
        for res in cls.resource_types_permissions:  # type: models.Resource
            if res.resource_type_name == resource_type_name:
                return cls.resource_types_permissions[res]
        return []

    def allowed_permissions(self, resource):
        # type: (ServiceOrResourceType) -> List[Permission]
        """
        Obtains the allowed permissions for or under the service according to provided service or resource.
        """
        if resource.resource_type == "service" and resource.type == self.service_type:
            return self.permissions
        return self.get_resource_permissions(resource.resource_type)

    def effective_permissions(self, user, resource, permissions=None, allow_match=True):
        # type: (models.User, ServiceOrResourceType, Optional[Collection[Permission]], bool) -> List[PermissionSet]
        """
        Obtains the effective permissions the user has over the specified resource.

        Recursively rewinds the resource tree from the specified resource up to the top-most parent service the resource
        resides under (or directly if the resource is the service) and retrieve permissions along the way that should be
        applied to children when using scoped-resource inheritance. Rewinding of the tree can terminate earlier when
        permissions can be immediately resolved such as when more restrictive conditions enforce denied access.

        Both user and group permission inheritance is resolved simultaneously to tree hierarchy with corresponding
        allow and deny conditions. User :term:`Direct Permissions` have priority over all its groups
        :term:`Inherited Permissions`, and denied permissions have priority over allowed access ones.

        All applicable permissions on the resource (as defined by :meth:`allowed_permissions`) will have their
        resolution (Allow/Deny) provided as output, unless a specific subset of permissions is requested using
        :paramref:`permissions`. Other permissions are ignored in this case to only resolve requested ones.
        For example, this parameter can be used to request only ACL resolution from specific permissions applicable
        for a given request, as obtained by :meth:`permission_requested`.

        Permissions scoped as `match` can be ignored using :paramref:`allow_match`, such as when the targeted resource
        does not exist.

        .. seealso::
            - :meth:`ServiceInterface.resource_requested`
        """
        if not permissions:
            permissions = self.allowed_permissions(resource)
        requested_perms = set(permissions)  # type: Set[Permission]
        effective_perms = dict()            # type: Dict[Permission, PermissionSet]

        # immediately return all permissions if user is an admin
        db_session = self.request.db
        admin_group = get_constant("MAGPIE_ADMIN_GROUP", self.request)
        admin_group = GroupService.by_group_name(admin_group, db_session=db_session)
        if admin_group in user.groups:  # noqa
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
                            effective_perms[perm_name] = resolved_perm
                            effective_level[perm_name] = current_level
                        # - If new permission is at *different* tree-level, it applies only if the group has higher
                        #   priority than the previous one, to respect the *closest* scope to the target resource.
                        #   Same priorities are ignored as they were already resolved by *closest* scope above.
                        # - Reset scope level with new permission such that another permission of same group priority as
                        #   that could be processed in next iteration can be compared against it, to resolve 'access'
                        #   priority between them.
                        elif perm_set.group_priority > prev_perm.group_priority:
                            effective_perms[perm_name] = perm_set
                            effective_level[perm_name] = current_level

            # don't bother moving to parent if everything is resolved already
            #   can only assume nothing left to resolve if all permissions are direct on user (highest priority)
            #   if any found permission is group inherited, higher level user permission could still override it
            if (len(effective_perms) == len(requested_perms) and
                    all(perm.type == PermissionType.DIRECT for perm in effective_perms.values())):
                break
            # otherwise, move to parent if any available, since we are not done rewinding the resource tree
            allow_match = False  # reset match not applicable anymore for following parent resources
            current_level += 1
            if resource.parent_id:
                resource = ResourceService.by_resource_id(resource.parent_id, db_session=db_session)
            else:
                resource = None

        # set deny for all still unresolved permissions from requested ones
        resolved_perms = set(effective_perms)
        missing_perms = set(permissions) - resolved_perms
        final_perms = set(effective_perms.values())  # type: Set[PermissionSet]
        for perm_name in missing_perms:
            perm = PermissionSet(perm_name, access=Access.DENY, scope=Scope.MATCH,
                                 typ=PermissionType.EFFECTIVE, reason=PERMISSION_REASON_DEFAULT)
            final_perms.add(perm)
        # enforce type and scope (use MATCH to make it explicit that it applies specifically for this resource)
        for perm in final_perms:
            perm.type = PermissionType.EFFECTIVE
            perm.scope = Scope.MATCH
        return list(final_perms)


class ServiceOWS(ServiceInterface):
    """
    Generic request-to-permission interpretation method of various ``OGC Web Service`` (OWS) implementations.
    """

    def __init__(self, service, request):
        # type: (models.Service, Request) -> None
        super(ServiceOWS, self).__init__(service, request)
        self.parser = ows_parser_factory(request)
        self.parser.parse(self.params_expected)  # run parsing to obtain guaranteed lowered-name parameters

    @abc.abstractmethod
    def resource_requested(self):
        raise NotImplementedError

    def permission_requested(self):
        # type: () -> Permission
        try:
            req = str(self.parser.params["request"]).lower()
            perm = Permission.get(req)
            if perm is None:
                raise NotImplementedError(
                    "Missing or unknown 'Permission' from OWS 'request' parameter: {!s}".format(req)
                )
            return perm
        except KeyError as exc:
            raise NotImplementedError("Exception: [{!r}] for class '{}'.".format(exc, type(self)))


class ServiceWPS(ServiceOWS):
    """
    Service that represents a ``Web Processing Service`` endpoint.
    """

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
        models.Process: [
            Permission.DESCRIBE_PROCESS,
            Permission.EXECUTE,
        ]
    }

    def resource_requested(self):
        wps_request = self.permission_requested()
        if wps_request == Permission.GET_CAPABILITIES:
            return self.service, True
        if wps_request in [Permission.DESCRIBE_PROCESS, Permission.EXECUTE]:
            wps_id = self.service.resource_id
            proc_id = self.parser.params["identifier"]
            if not proc_id:
                return self.service, False
            proc = models.find_children_by_name(proc_id, parent_id=wps_id, db_session=self.request.db)
            if proc:
                return proc, True
            return self.service, False
        raise NotImplementedError("Unknown WPS operation for permission: {}".format(wps_request))


class ServiceBaseWMS(ServiceOWS):
    """
    Service that represents basic capabilities of a ``Web Map Service`` endpoint.
    """

    @abc.abstractmethod
    def resource_requested(self):
        raise NotImplementedError

    permissions = [
        Permission.GET_CAPABILITIES,
        Permission.GET_MAP,
        Permission.GET_FEATURE_INFO,
        Permission.GET_LEGEND_GRAPHIC,
        Permission.GET_METADATA,
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
    """
    service_type = "ncwms"

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

            db_session = self.request.db
            file_parts = netcdf_file.split("/")
            while found_child and file_parts:
                part = file_parts.pop(0)
                res_id = found_child.resource_id
                found_child = models.find_children_by_name(part, parent_id=res_id, db_session=db_session)
            # target resource reached if no more parts to process, otherwise we have some parent (minimally the service)
            target = not len(file_parts)
        return found_child, target


class ServiceGeoserverWMS(ServiceBaseWMS):
    """
    Service that represents a ``Web Map Service`` endpoint with functionalities specific to ``GeoServer``.
    """
    service_type = "geoserverwms"

    resource_types_permissions = {
        models.Workspace: [
            Permission.GET_CAPABILITIES,
            Permission.GET_MAP,
            Permission.GET_FEATURE_INFO,
            Permission.GET_LEGEND_GRAPHIC,
            Permission.GET_METADATA,
        ]
    }

    def resource_requested(self):
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
        if len(parts_lower) > 1 and parts_lower[1] == "wms":
            workspace_name = path_parts[0]
        if permission == Permission.GET_CAPABILITIES:
            # here we need to check the workspace in the path
            #   /geoserver/wms?request=getcapabilities (get all workspaces)
            #   /geoserver/WATERSHED/wms?request=getcapabilities (only for the workspace in the path)
            if not path_parts or "wms" not in parts_lower or (len(parts_lower) == 1 and parts_lower[0] == "wms"):
                return self.service, True
        else:
            # those two request lead to the same thing so, here we need to check the workspace in the layer
            #   /geoserver/WATERSHED/wms?layers=WATERSHED:BV_1NS&request=getmap
            #   /geoserver/wms?layers=WATERERSHED:BV1_NS&request=getmap
            if not workspace_name:
                layer_name = self.parser.params["layers"] or ""
                workspace_name = layer_name.split(":")[0]
        if not workspace_name:
            return self.service, False
        workspace = models.find_children_by_name(child_name=workspace_name,
                                                 parent_id=self.service.resource_id,
                                                 db_session=self.request.db)
        if workspace:
            return workspace, True
        return self.service, False


class ServiceAccess(ServiceInterface):
    service_type = "access"

    permissions = [Permission.ACCESS]

    params_expected = []

    resource_types_permissions = {}

    def resource_requested(self):
        return self.service, True

    def permission_requested(self):
        return Permission.ACCESS


class ServiceAPI(ServiceInterface):
    """
    Service that provides resources per individual request path segments.
    """
    service_type = "api"

    permissions = models.Route.permissions

    params_expected = []

    resource_types_permissions = {
        models.Route: models.Route.permissions
    }

    def resource_requested(self):
        # type: () -> Optional[Tuple[ServiceOrResourceType, bool]]

        route_parts = self._get_request_path_parts()
        if not route_parts:
            return self.service, True
        route_found = route_child = self.service

        # find deepest possible resource matching sub-route name
        while route_child and route_parts:
            part_name = route_parts.pop(0)
            route_res_id = route_child.resource_id
            route_child = models.find_children_by_name(part_name, parent_id=route_res_id, db_session=self.request.db)
            if route_child:
                route_found = route_child

        # target reached if no more parts to process, otherwise we have some parent (minimally the service)
        route_target = not len(route_parts) and route_child is not None
        return route_found, route_target

    def permission_requested(self):
        if self.request.method.upper() in ["GET", "HEAD"]:
            return Permission.READ
        return Permission.WRITE


class ServiceWFS(ServiceOWS):
    """
    Service that represents a ``Web Feature Service`` endpoint.
    """
    service_type = "wfs"

    permissions = [
        Permission.GET_CAPABILITIES,
        Permission.DESCRIBE_FEATURE_TYPE,
        Permission.GET_FEATURE,
        Permission.LOCK_FEATURE,
        Permission.TRANSACTION,
    ]

    params_expected = [
        "service",
        "request",
        "version",
        "typenames"
    ]

    resource_types_permissions = {}

    def resource_requested(self):
        return self.service, True   # no children resource, so can only be the service


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

    params_expected = [
        "request"
    ]

    resource_types_permissions = {
        models.Directory: permissions,
        models.File: permissions,
    }

    def __init__(self, *_, **__):
        super(ServiceTHREDDS, self).__init__(*_, **__)
        self._config = None

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
            child_res_id = child_resource.resource_id
            child_resource = models.find_children_by_name(part_name, parent_id=child_res_id, db_session=self.request.db)
            if child_resource:
                found_resource = child_resource

        # target resource reached if no more parts to process, otherwise we have some parent (minimally the service)
        target = not len(path_parts) and child_resource is not None
        return found_resource, target

    def permission_requested(self):
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


SERVICE_TYPE_DICT = dict()
for svc in [ServiceAccess, ServiceAPI, ServiceGeoserverWMS, ServiceNCWMS2, ServiceTHREDDS, ServiceWFS, ServiceWPS]:
    if svc.service_type in SERVICE_TYPE_DICT:
        raise KeyError("Duplicate resource type identifiers not allowed")
    SERVICE_TYPE_DICT[svc.service_type] = svc


def service_factory(service, request):
    # type: (models.Service, Request) -> ServiceInterface
    """
    Retrieve the specific service class from the provided database service entry.
    """
    ax.verify_param(service, param_compare=models.Service, is_type=True,
                    http_error=HTTPBadRequest, content={"service": repr(service)},
                    msg_on_fail="Cannot process invalid service object")
    service_type = ax.evaluate_call(lambda: service.type, http_error=HTTPInternalServerError,
                                    msg_on_fail="Cannot retrieve service type from object")
    ax.verify_param(service_type, is_in=True, param_compare=SERVICE_TYPE_DICT.keys(),
                    http_error=HTTPNotImplemented, content={"service_type": service_type},
                    msg_on_fail="Undefined service type mapping to service object")
    return ax.evaluate_call(lambda: SERVICE_TYPE_DICT[service_type](service, request),
                            http_error=HTTPInternalServerError,
                            msg_on_fail="Failed to find requested service type.")


def invalidate_service(service_name):
    # type: (Str) -> None
    """
    Invalidates any caching reference to the specified service name.
    """
    # pylint: disable=W0212,protected-access
    try:
        # could fail if twitcher was not installed
        from magpie.adapter.magpieowssecurity import MagpieOWSSecurity  # noqa

        if "service" in cache_regions:
            region_invalidate(MagpieOWSSecurity._get_service_cached, "service", service_name)  # noqa
    except ImportError:
        LOGGER.warning("Could not invalidate cache of service: [%s]", service_name)

    if "acl" in cache_regions:
        cache_keys = (service_name, )  # (service_name, request_method, request_path, user_id)
        region_invalidate(ServiceInterface._get_acl_cached, "acl", *cache_keys)  # noqa
