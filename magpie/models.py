from magpie.api.exception import evaluate_call
from magpie.definitions.pyramid_definitions import ALLOW, ALL_PERMISSIONS, HTTPInternalServerError
from magpie.definitions.sqlalchemy_definitions import sa, declared_attr, relationship, declarative_base
from magpie.definitions.ziggurat_definitions import (
    get_db_session,
    permission_to_pyramid_acls,
    ziggurat_model_init,
    BaseModel,
    ExternalIdentityMixin,
    GroupMixin,
    GroupPermissionMixin,
    GroupResourcePermissionMixin,
    ResourceMixin,
    ResourceTreeService,
    ResourceTreeServicePostgreSQL,
    UserGroupMixin,
    UserMixin,
    UserPermissionMixin,
    UserResourcePermissionMixin,
    UserService,
    BaseService,
)
from magpie.permissions import Permission
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Str  # noqa: F401

Base = declarative_base()


def get_session_callable(request):
    return request.db


class Group(GroupMixin, Base):
    def get_member_count(self, db_session=None):
        return BaseService.all(UserGroup, db_session=db_session).filter(UserGroup.group_id == self.id).count()


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
        acl = []

        if self.owner_user_id:
            acl.extend([(ALLOW, self.owner_user_id, ALL_PERMISSIONS,), ])

        if self.owner_group_id:
            acl.extend([(ALLOW, "group:%s" % self.owner_group_id, ALL_PERMISSIONS,), ])
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
    def __init__(self, request):
        self.__acl__ = []
        if request.user:
            permissions = UserService.permissions(request.user, request.db)
            self.__acl__.extend(permission_to_pyramid_acls(permissions))


class Service(Resource):
    """
    Resource of `service` type.
    """

    __tablename__ = u"services"

    resource_id = sa.Column(sa.Integer(),
                            sa.ForeignKey("resources.resource_id",
                                          onupdate="CASCADE",
                                          ondelete="CASCADE", ),
                            primary_key=True, )

    resource_type_name = u"service"
    __mapper_args__ = {u"polymorphic_identity": resource_type_name,
                       u"inherit_condition": resource_id == Resource.resource_id}

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
        Identifier matching ``magpie.helpers.SyncServiceInterface.sync_type``.
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
    resource_type_name = u"file"
    __mapper_args__ = {u"polymorphic_identity": resource_type_name}


class Directory(Resource, PathBase):
    resource_type_name = u"directory"
    __mapper_args__ = {u"polymorphic_identity": resource_type_name}


class Workspace(Resource):
    resource_type_name = u"workspace"
    __mapper_args__ = {u"polymorphic_identity": resource_type_name}

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
    resource_type_name = u"route"
    __mapper_args__ = {u"polymorphic_identity": resource_type_name}

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
    pass


ziggurat_model_init(User, Group, UserGroup, GroupPermission, UserPermission,
                    UserResourcePermission, GroupResourcePermission, Resource,
                    ExternalIdentity, passwordmanager=None)

resource_tree_service = ResourceTreeService(ResourceTreeServicePostgreSQL)
remote_resource_tree_service = RemoteResourceTreeService(RemoteResourceTreeServicePostgresSQL)

RESOURCE_TYPE_DICT = dict()
for res in [Service, Directory, File, Workspace, Route]:
    if res.resource_type_name in RESOURCE_TYPE_DICT:
        raise KeyError("Duplicate resource type identifiers not allowed")
    RESOURCE_TYPE_DICT[res.resource_type_name] = res


def resource_factory(**kwargs):
    resource_type = evaluate_call(lambda: kwargs["resource_type"], httpError=HTTPInternalServerError,
                                  msgOnFail="kwargs do not contain required 'resource_type'",
                                  content={u"kwargs": repr(kwargs)})
    return evaluate_call(lambda: RESOURCE_TYPE_DICT[resource_type](**kwargs), httpError=HTTPInternalServerError,
                         msgOnFail="kwargs unpacking failed from specified 'resource_type' and 'RESOURCE_TYPE_DICT'",
                         content={u"kwargs": repr(kwargs), u"RESOURCE_TYPE_DICT": repr(RESOURCE_TYPE_DICT)})


def find_children_by_name(child_name, parent_id, db_session):
    tree_struct = resource_tree_service.from_parent_deeper(parent_id=parent_id, limit_depth=1, db_session=db_session)
    tree_level_entries = [node for node in tree_struct]
    tree_level_filtered = [node.Resource for node in tree_level_entries if
                           node.Resource.resource_name.lower() == child_name.lower()]
    return tree_level_filtered.pop() if len(tree_level_filtered) else None
