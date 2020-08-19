from typing import TYPE_CHECKING

import sqlalchemy as sa
from pyramid.httpexceptions import HTTPInternalServerError
from pyramid.security import ALL_PERMISSIONS, Allow, Authenticated
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship
from ziggurat_foundations import ziggurat_model_init
from ziggurat_foundations.models.base import BaseModel, get_db_session
from ziggurat_foundations.models.external_identity import ExternalIdentityMixin
from ziggurat_foundations.models.group import GroupMixin
from ziggurat_foundations.models.group_permission import GroupPermissionMixin
from ziggurat_foundations.models.group_resource_permission import GroupResourcePermissionMixin
from ziggurat_foundations.models.resource import ResourceMixin
from ziggurat_foundations.models.services import BaseService
from ziggurat_foundations.models.services.resource_tree import ResourceTreeService
from ziggurat_foundations.models.services.resource_tree_postgres import ResourceTreeServicePostgreSQL
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.models.user import UserMixin
from ziggurat_foundations.models.user_group import UserGroupMixin
from ziggurat_foundations.models.user_permission import UserPermissionMixin
from ziggurat_foundations.models.user_resource_permission import UserResourcePermissionMixin
from ziggurat_foundations.permissions import permission_to_pyramid_acls

from magpie.api.exception import evaluate_call
from magpie.constants import get_constant
from magpie.permissions import Permission

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, Type
    from magpie.typedefs import Str

Base = declarative_base()   # pylint: disable=C0103,invalid-name


def get_session_callable(request):
    return request.db


class Group(GroupMixin, Base):
    def get_member_count(self, db_session=None):
        return BaseService.all(UserGroup, db_session=db_session).filter(UserGroup.group_id == self.id).count()

    @declared_attr
    def discoverable(self):
        """Indicates if the group is discoverable for users to self-register to it."""
        return sa.Column(sa.Boolean(), default=False)


class GroupPermission(GroupPermissionMixin, Base):
    pass


class UserGroup(UserGroupMixin, Base):
    pass


class GroupResourcePermission(GroupResourcePermissionMixin, Base):
    pass


class Resource(ResourceMixin, Base):
    # required resource type identifier (unique)
    resource_type_name = None       # type: Str

    child_resource_allowed = True
    resource_display_name = sa.Column(sa.Unicode(100), nullable=True)

    # reference to top-most service under which the resource is nested
    # if the resource is the service, id is None (NULL)
    @declared_attr
    def root_service_id(self):
        return sa.Column(sa.Integer,
                         sa.ForeignKey("services.resource_id",
                                       onupdate="CASCADE",
                                       ondelete="SET NULL"), index=True)

    @property
    def __acl__(self):
        """User or group that owns a resource are granted full access to it."""
        acl = []
        if self.owner_user_id:
            acl.extend([(Allow, self.owner_user_id, ALL_PERMISSIONS,), ])
        if self.owner_group_id:
            acl.extend([(Allow, "group:%s" % self.owner_group_id, ALL_PERMISSIONS,), ])
        return acl


class UserPermission(UserPermissionMixin, Base):
    pass


class UserResourcePermission(UserResourcePermissionMixin, Base):
    pass


class User(UserMixin, Base):
    def __str__(self):
        return "<User: %s, %s>" % (self.id, self.user_name)


class ExternalIdentity(ExternalIdentityMixin, Base):
    pass


class RootFactory(object):
    """Used to build base Access Control List (ACL) of the request user.

    All API and UI routes will employ this set of effective principals to determine if the user is authorized to access
    the pyramid view according to the ``permission`` value it was configured with.

    .. note::
        Keep in mind that `Magpie` is configured with default permission
        :py:data:`magpie.constants.MAGPIE_ADMIN_PERMISSION`.
        Views that require more permissive authorization must be overridden with ``permission`` argument.

    .. seealso::
        - ``set_default_permission`` within :func:`magpie.includeme` initialization steps
    """
    def __init__(self, request):
        self.request = request

    @property
    def __acl__(self):
        """Administrators have all permissions, user/group-specific permissions added if user is logged in."""
        user = self.request.user
        if user:
            permissions = UserService.permissions(user, self.request.db)
            user_acl = permission_to_pyramid_acls(permissions)
            auth_acl = [(Allow, user.id, Authenticated)]
            return user_acl + auth_acl
        return []


class UserFactory(RootFactory):
    def __init__(self, request):
        super(UserFactory, self).__init__(request)
        self.path_user = None

    def __getitem__(self, user_name):
        if user_name == get_constant("MAGPIE_LOGGED_USER", self.request):
            self.path_user = self.request.user
        else:
            self.path_user = UserService.by_user_name(user_name, self.request.db)
        if self.path_user is not None:
            self.path_user.__parent__ = self
            self.path_user.__name__ = user_name
        return self.path_user

    @property
    def __acl__(self):
        """
        Grant access to authenticated request user if it is the same as referenced user by path parameter
        (either from explicit name or logged reserved keyword), to allow operations for itself.
        """
        acl = super(UserFactory, self).__acl__
        user = self.request.user
        if user and self.path_user and user.id == self.path_user.id:
            return acl + [(Allow, user.id, "MAGPIE_LOGGED_USER")]
        return acl


class Service(Resource):
    """
    Resource of `service` type.
    """

    __tablename__ = "services"

    resource_id = sa.Column(sa.Integer(),
                            sa.ForeignKey("resources.resource_id",
                                          onupdate="CASCADE",
                                          ondelete="CASCADE", ),
                            primary_key=True, )

    resource_type_name = "service"
    __mapper_args__ = {"polymorphic_identity": resource_type_name,
                       "inherit_condition": resource_id == Resource.resource_id}

    @property
    def permissions(self):
        raise TypeError("Service permissions must be accessed by 'magpie.services.ServiceInterface' "
                        "instead of 'magpie.models.Service'.")

    @declared_attr
    def url(self):
        # http://localhost:8083
        return sa.Column(sa.UnicodeText(), unique=True)

    @declared_attr
    def type(self):
        """
        Identifier matching ``magpie.services.ServiceInterface.service_type``.
        """
        # wps, wms, thredds,...
        return sa.Column(sa.UnicodeText())

    @declared_attr
    def sync_type(self):
        """
        Identifier matching ``magpie.cli.SyncServiceInterface.sync_type``.
        """
        # project-api, geoserver-api,...
        return sa.Column(sa.UnicodeText(), nullable=True)

    @staticmethod
    def by_service_name(service_name, db_session):
        db = get_db_session(db_session)
        service = db.query(Service).filter(Resource.resource_name == service_name).first()
        return service


class PathBase(object):
    permissions = [
        Permission.READ,
        Permission.WRITE,
        Permission.GET_CAPABILITIES,
        Permission.GET_MAP,
        Permission.GET_FEATURE_INFO,
        Permission.GET_LEGEND_GRAPHIC,
        Permission.GET_METADATA,
    ]


class File(Resource, PathBase):
    child_resource_allowed = False
    resource_type_name = "file"
    __mapper_args__ = {"polymorphic_identity": resource_type_name}


class Directory(Resource, PathBase):
    resource_type_name = "directory"
    __mapper_args__ = {"polymorphic_identity": resource_type_name}


class Workspace(Resource):
    resource_type_name = "workspace"
    __mapper_args__ = {"polymorphic_identity": resource_type_name}

    permissions = [
        Permission.GET_CAPABILITIES,
        Permission.GET_MAP,
        Permission.GET_FEATURE_INFO,
        Permission.GET_LEGEND_GRAPHIC,
        Permission.GET_METADATA,
        Permission.GET_FEATURE,
        Permission.DESCRIBE_FEATURE_TYPE,
        Permission.LOCK_FEATURE,
        Permission.TRANSACTION,
    ]


class Route(Resource):
    resource_type_name = "route"
    __mapper_args__ = {"polymorphic_identity": resource_type_name}

    permissions = [
        Permission.READ,            # access with inheritance (this route and all under it)
        Permission.WRITE,           # access with inheritance (this route and all under it)
        Permission.READ_MATCH,      # access without inheritance (only on this specific route)
        Permission.WRITE_MATCH,     # access without inheritance (only on this specific route)
    ]


class RemoteResource(BaseModel, Base):
    __tablename__ = "remote_resources"

    __possible_permissions__ = ()
    _ziggurat_services = [ResourceTreeService]

    resource_id = sa.Column(sa.Integer(), primary_key=True, nullable=False, autoincrement=True)
    service_id = sa.Column(sa.Integer(),
                           sa.ForeignKey("services.resource_id",
                                         onupdate="CASCADE",
                                         ondelete="CASCADE"),
                           index=True,
                           nullable=False)
    parent_id = sa.Column(sa.Integer(),
                          sa.ForeignKey("remote_resources.resource_id",
                                        onupdate="CASCADE",
                                        ondelete="SET NULL"),
                          nullable=True)
    ordering = sa.Column(sa.Integer(), default=0, nullable=False)
    resource_name = sa.Column(sa.Unicode(100), nullable=False)
    resource_display_name = sa.Column(sa.Unicode(100), nullable=True)
    resource_type = sa.Column(sa.Unicode(30), nullable=False)

    def __repr__(self):
        info = self.resource_type, self.resource_name, self.resource_id, self.ordering, self.parent_id
        return "<RemoteResource: %s, %s, id: %s position: %s, parent_id: %s>" % info


class RemoteResourcesSyncInfo(BaseModel, Base):
    __tablename__ = "remote_resources_sync_info"

    id = sa.Column(sa.Integer(), primary_key=True, nullable=False, autoincrement=True)
    service_id = sa.Column(sa.Integer(),
                           sa.ForeignKey("services.resource_id",
                                         onupdate="CASCADE",
                                         ondelete="CASCADE"),
                           index=True,
                           nullable=False)
    service = relationship("Service", foreign_keys=[service_id])
    remote_resource_id = sa.Column(sa.Integer(),
                                   sa.ForeignKey("remote_resources.resource_id", onupdate="CASCADE",
                                                 ondelete="CASCADE"))
    last_sync = sa.Column(sa.DateTime(), nullable=True)

    @staticmethod
    def by_service_id(service_id, session):
        condition = RemoteResourcesSyncInfo.service_id == service_id
        service_info = session.query(RemoteResourcesSyncInfo).filter(condition).first()
        return service_info

    def __repr__(self):
        last_modified = self.last_sync.strftime("%Y-%m-%dT%H:%M:%S") if self.last_sync else None
        info = self.service_id, last_modified, self.id
        return "<RemoteResourcesSyncInfo service_id: %s, last_sync: %s, id: %s>" % info


class RemoteResourceTreeService(ResourceTreeService):
    def __init__(self, service_cls):
        self.model = RemoteResource
        super(RemoteResourceTreeService, self).__init__(service_cls)


class RemoteResourceTreeServicePostgresSQL(ResourceTreeServicePostgreSQL):
    """
    This is necessary, because ResourceTreeServicePostgresSQL.model is the Resource class. If we want to change it for a
    RemoteResource, we need this class.

    The ResourceTreeService.__init__ call sets the model.
    """


ziggurat_model_init(User, Group, UserGroup, GroupPermission, UserPermission,
                    UserResourcePermission, GroupResourcePermission, Resource,
                    ExternalIdentity, passwordmanager=None)

RESOURCE_TREE_SERVICE = ResourceTreeService(ResourceTreeServicePostgreSQL)
REMOTE_RESOURCE_TREE_SERVICE = RemoteResourceTreeService(RemoteResourceTreeServicePostgresSQL)

RESOURCE_TYPE_DICT = dict()  # type: Dict[Str, Type[Resource]]
for res in [Service, Directory, File, Workspace, Route]:
    if res.resource_type_name in RESOURCE_TYPE_DICT:
        raise KeyError("Duplicate resource type identifiers not allowed")
    RESOURCE_TYPE_DICT[res.resource_type_name] = res


def resource_factory(**kwargs):
    resource_type = evaluate_call(lambda: kwargs["resource_type"], http_error=HTTPInternalServerError,
                                  msg_on_fail="kwargs do not contain required 'resource_type'",
                                  content={"kwargs": repr(kwargs)})
    return evaluate_call(lambda: RESOURCE_TYPE_DICT[resource_type](**kwargs),  # noqa
                         http_error=HTTPInternalServerError,
                         msg_on_fail="kwargs unpacking failed from specified 'resource_type' and 'RESOURCE_TYPE_DICT'",
                         content={"kwargs": repr(kwargs), "RESOURCE_TYPE_DICT": repr(RESOURCE_TYPE_DICT)})


def find_children_by_name(child_name, parent_id, db_session):
    tree_struct = RESOURCE_TREE_SERVICE.from_parent_deeper(parent_id=parent_id, limit_depth=1, db_session=db_session)
    tree_level_filtered = [node.Resource for node in list(tree_struct) if
                           node.Resource.resource_name.lower() == child_name.lower()]
    return tree_level_filtered.pop() if len(tree_level_filtered) else None
