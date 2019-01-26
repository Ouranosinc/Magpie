from magpie.definitions.pyramid_definitions import *
from magpie.definitions.ziggurat_definitions import *
from magpie.definitions.sqlalchemy_definitions import *
from magpie.api.api_except import evaluate_call
from magpie.permissions import *

Base = declarative_base()


def get_session_callable(request):
    return request.db


def get_user(request):
    user_id = request.unauthenticated_userid
    db_session = get_session_callable(request)
    if user_id is not None:
        return UserService.by_id(user_id, db_session=db_session)


class Group(GroupMixin, Base):
    pass


class GroupPermission(GroupPermissionMixin, Base):
    pass


class UserGroup(UserGroupMixin, Base):
    pass


class GroupResourcePermission(GroupResourcePermissionMixin, Base):
    pass


class Resource(ResourceMixin, Base):
    # ... your own properties....

    # example implementation of ACL for pyramid application
    permission_names = []
    child_resource_allowed = True

    resource_display_name = sa.Column(sa.Unicode(100), nullable=True)

    # reference to top-most service under which the resource is nested
    # if the resource is the service, id is None (NULL)
    @declared_attr
    def root_service_id(self):
        return sa.Column(sa.Integer,
                         sa.ForeignKey('services.resource_id',
                                       onupdate='CASCADE',
                                       ondelete='SET NULL'), index=True)

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
    # ... your own properties....
    pass


class ExternalIdentity(ExternalIdentityMixin, Base):
    pass


class RootFactory(object):
    def __init__(self, request):
        self.__acl__ = []
        if request.user:
            permissions = UserService.permissions(request.user, request.db)
            for outcome, perm_user, perm_name in permission_to_pyramid_acls(permissions):
                self.__acl__.append((outcome, perm_user, perm_name))


# you can define multiple resource derived models to build a complex
# application like CMS, forum or other permission based solution

class Service(Resource):
    """
    Resource of `service` type
    """

    __tablename__ = u'services'

    resource_id = sa.Column(sa.Integer(),
                            sa.ForeignKey('resources.resource_id',
                                          onupdate='CASCADE',
                                          ondelete='CASCADE', ),
                            primary_key=True, )

    resource_type_name = u'service'
    __mapper_args__ = {u'polymorphic_identity': resource_type_name,
                       u'inherit_condition': resource_id == Resource.resource_id}

    # ... your own properties....

    @declared_attr
    def url(self):
        # http://localhost:8083
        return sa.Column(sa.UnicodeText(), unique=True)

    @declared_attr
    def type(self):
        # wps, wms, thredds, ...
        return sa.Column(sa.UnicodeText())

    @declared_attr
    def sync_type(self):
        # project-api, geoserver-api, ...
        return sa.Column(sa.UnicodeText(), nullable=True)

    @staticmethod
    def by_service_name(service_name, db_session):
        db = get_db_session(db_session)
        service = db.query(Service).filter(Resource.resource_name == service_name).first()
        return service

    def permission_requested(self, request):
        raise NotImplementedError

    def extend_acl(self, resource, user):
        # Ownership acl
        for ace in resource.__acl__:
            self.__acl__.append(ace)
        # Custom acl
        permissions = resource.perms_for_user(user)
        for outcome, perm_user, perm_name in permission_to_pyramid_acls(permissions):
            self.__acl__.append((outcome, perm_user, perm_name,))


class Path(object):
    permission_names = [
        PERMISSION_READ,
        PERMISSION_WRITE,
        PERMISSION_GET_CAPABILITIES,
        PERMISSION_GET_MAP,
        PERMISSION_GET_FEATURE_INFO,
        PERMISSION_GET_LEGEND_GRAPHIC,
        PERMISSION_GET_METADATA,
    ]


class File(Resource, Path):
    child_resource_allowed = False
    resource_type_name = u'file'
    __mapper_args__ = {u'polymorphic_identity': resource_type_name}


class Directory(Resource, Path):
    resource_type_name = u'directory'
    __mapper_args__ = {u'polymorphic_identity': resource_type_name}


class Workspace(Resource):
    resource_type_name = u'workspace'
    __mapper_args__ = {u'polymorphic_identity': resource_type_name}

    permission_names = [
        PERMISSION_GET_CAPABILITIES,
        PERMISSION_GET_MAP,
        PERMISSION_GET_FEATURE_INFO,
        PERMISSION_GET_LEGEND_GRAPHIC,
        PERMISSION_GET_METADATA,
        PERMISSION_GET_FEATURE,
        PERMISSION_DESCRIBE_FEATURE_TYPE,
        PERMISSION_LOCK_FEATURE,
        PERMISSION_TRANSACTION,
    ]


class Route(Resource):
    resource_type_name = u'route'
    __mapper_args__ = {u'polymorphic_identity': resource_type_name}

    permission_names = [
        PERMISSION_READ,            # access with inheritance (this route and all under it)
        PERMISSION_WRITE,           # access with inheritance (this route and all under it)
        PERMISSION_READ_MATCH,      # access without inheritance (only on this specific route)
        PERMISSION_WRITE_MATCH,     # access without inheritance (only on this specific route)
    ]


class RemoteResource(BaseModel, Base):
    __tablename__ = "remote_resources"

    __possible_permissions__ = ()
    _ziggurat_services = [ResourceTreeService]

    resource_id = sa.Column(sa.Integer(), primary_key=True, nullable=False, autoincrement=True)
    service_id = sa.Column(sa.Integer(),
                           sa.ForeignKey('services.resource_id',
                                         onupdate='CASCADE',
                                         ondelete='CASCADE'),
                           index=True,
                           nullable=False)
    parent_id = sa.Column(sa.Integer(),
                          sa.ForeignKey('remote_resources.resource_id',
                                        onupdate='CASCADE',
                                        ondelete='SET NULL'),
                          nullable=True)
    ordering = sa.Column(sa.Integer(), default=0, nullable=False)
    resource_name = sa.Column(sa.Unicode(100), nullable=False)
    resource_display_name = sa.Column(sa.Unicode(100), nullable=True)
    resource_type = sa.Column(sa.Unicode(30), nullable=False)

    def __repr__(self):
        info = self.resource_type, self.resource_name, self.resource_id, self.ordering, self.parent_id
        return '<RemoteResource: %s, %s, id: %s position: %s, parent_id: %s>' % info


class RemoteResourcesSyncInfo(BaseModel, Base):
    __tablename__ = "remote_resources_sync_info"

    id = sa.Column(sa.Integer(), primary_key=True, nullable=False, autoincrement=True)
    service_id = sa.Column(sa.Integer(),
                           sa.ForeignKey('services.resource_id',
                                         onupdate='CASCADE',
                                         ondelete='CASCADE'),
                           index=True,
                           nullable=False)
    service = relationship("Service", foreign_keys=[service_id])
    remote_resource_id = sa.Column(sa.Integer(),
                                   sa.ForeignKey('remote_resources.resource_id', onupdate='CASCADE',
                                                 ondelete='CASCADE'))
    last_sync = sa.Column(sa.DateTime(), nullable=True)

    @staticmethod
    def by_service_id(service_id, session):
        condition = RemoteResourcesSyncInfo.service_id == service_id
        service_info = session.query(RemoteResourcesSyncInfo).filter(condition).first()
        return service_info

    def __repr__(self):
        last_modified = self.last_sync.strftime("%Y-%m-%dT%H:%M:%S") if self.last_sync else None
        info = self.service_id, last_modified, self.id
        return '<RemoteResourcesSyncInfo service_id: %s, last_sync: %s, id: %s>' % info


class RemoteResourceTreeService(ResourceTreeService):
    def __init__(self, service_cls):
        self.model = RemoteResource
        super(RemoteResourceTreeService, self).__init__(service_cls)


class RemoteResourceTreeServicePostgresSQL(ResourceTreeServicePostgreSQL):
    """
    This is necessary, because ResourceTreeServicePostgresSQL.model is the Resource class.
    If we want to change it for a RemoteResource, we need this class.

    The ResourceTreeService.__init__ call sets the model.
    """
    pass


ziggurat_model_init(User, Group, UserGroup, GroupPermission, UserPermission,
                    UserResourcePermission, GroupResourcePermission, Resource,
                    ExternalIdentity, passwordmanager=None)

resource_tree_service = ResourceTreeService(ResourceTreeServicePostgreSQL)
remote_resource_tree_service = RemoteResourceTreeService(RemoteResourceTreeServicePostgresSQL)

resource_type_dict = {
    Service.resource_type_name:     Service,
    Directory.resource_type_name:   Directory,
    File.resource_type_name:        File,
    Workspace.resource_type_name:   Workspace,
    Route.resource_type_name:       Route,
}


def resource_factory(**kwargs):
    resource_type = evaluate_call(lambda: kwargs['resource_type'], httpError=HTTPInternalServerError,
                                  msgOnFail="kwargs do not contain required `resource_type`",
                                  content={u'kwargs': repr(kwargs)})
    return evaluate_call(lambda: resource_type_dict[resource_type](**kwargs), httpError=HTTPInternalServerError,
                         msgOnFail="kwargs unpacking failed from specified `resource_type` and `resource_type_dict`",
                         content={u'kwargs': repr(kwargs), u'resource_type_dict': repr(resource_type_dict)})


def get_all_resource_permission_names():
    all_permission_names_list = set()
    for service_type in resource_type_dict.keys():
        all_permission_names_list.update(resource_type_dict[service_type].permission_names)
    return all_permission_names_list


def find_children_by_name(child_name, parent_id, db_session):
    tree_struct = resource_tree_service.from_parent_deeper(parent_id=parent_id, limit_depth=1, db_session=db_session)
    tree_level_entries = [node for node in tree_struct]
    tree_level_filtered = [node.Resource for node in tree_level_entries if
                           node.Resource.resource_name.lower() == child_name.lower()]
    return tree_level_filtered.pop() if len(tree_level_filtered) else None
