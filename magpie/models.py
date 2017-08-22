from pyramid.security import Allow,Everyone
from pyramid.security import ALL_PERMISSIONS
from ziggurat_foundations.models.external_identity import ExternalIdentityMixin
from ziggurat_foundations.models.group import GroupMixin
from ziggurat_foundations.models.group_permission import GroupPermissionMixin
from ziggurat_foundations.models.group_resource_permission import GroupResourcePermissionMixin
from ziggurat_foundations.models.resource import ResourceMixin
from ziggurat_foundations.models.user import UserMixin
from ziggurat_foundations.models.user_group import UserGroupMixin
from ziggurat_foundations.models.user_permission import UserPermissionMixin
from ziggurat_foundations.models.user_resource_permission import UserResourcePermissionMixin
from ziggurat_foundations import ziggurat_model_init
from sqlalchemy.ext.declarative import declarative_base
from ziggurat_foundations.models.base import get_db_session
import sqlalchemy as sa
from ziggurat_foundations.permissions import permission_to_pyramid_acls
from sqlalchemy.ext.declarative import declared_attr
from ziggurat_foundations.models import groupfinder as gf
from ziggurat_foundations.models.services.resource_tree import ResourceTreeService
from ziggurat_foundations.models.services.resource_tree_postgres import ResourceTreeServicePostgreSQL





Base = declarative_base()
group_finder = gf

def get_session_callable(request):
    return request.db


def get_user(request):
    userid = request.unauthenticated_userid
    db_session = get_session_callable(request)
    if userid is not None:
        return User.by_id(userid, db_session=db_session)


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

    # example implementation of ACLS for pyramid application
    permission_names = []

    @property
    def __acl__(self):
        acls = []

        if self.owner_user_id:
            acls.extend([(Allow, self.owner_user_id, ALL_PERMISSIONS,), ])

        if self.owner_group_id:
            acls.extend([(Allow, "group:%s" % self.owner_group_id,
                          ALL_PERMISSIONS,), ])
        return acls

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
            for outcome, perm_user, perm_name in permission_to_pyramid_acls(request.user.permissions):
                self.__acl__.append((outcome, perm_user, perm_name))


# you can define multiple resource derived models to build a complex
# application like CMS, forum or other permission based solution

class Service(Resource):
    """
    Resource of `service` type
    """

    __tablename__ = 'services'
    __mapper_args__ = {'polymorphic_identity': 'service'}

    resource_id = sa.Column(sa.Integer(),
                            sa.ForeignKey('resources.resource_id',
                                          onupdate='CASCADE',
                                          ondelete='CASCADE', ),
                            primary_key=True, )

    # ... your own properties....
    url = sa.Column(sa.UnicodeText(), unique=True)  # http://localhost:8083
    type = sa.Column(sa.UnicodeText())  # wps, wms, thredds, ...

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


class Directory(Resource):
    __mapper_args__ = {'polymorphic_identity': 'directory'}
    permission_names = ['download']


class File(Resource):
    __mapper_args__ = {'polymorphic_identity': 'file'}
    permission_names = ['download']


class Workspace(Resource):
    __mapper_args__ = {'polymorphic_identity': 'workspace'}
    permission_names = ['getcapabilities',
                        'getmap',
                        'getfeatureinfo',
                        'getlegendgraphic',
                        'getmetadata',
                        'describefeaturetype',
                        'getfeature',
                        'lockfeature',
                        'transaction']




ziggurat_model_init(User, Group, UserGroup, GroupPermission, UserPermission,
               UserResourcePermission, GroupResourcePermission, Resource,
               ExternalIdentity, passwordmanager=None)

resource_tree_service = ResourceTreeService(ResourceTreeServicePostgreSQL)

resource_type_dico = {'service': Service, 'directory': Directory, 'file': File, 'workspace': Workspace}






def resource_factory(**kwargs):
    try:
        resource_type = kwargs['resource_type']
    except Exception, e:
        raise Exception(e.message)
    return resource_type_dico[resource_type](**kwargs)


def get_all_resource_permission_names():
    all_permission_names_list = set()
    for service_type in resource_type_dico.keys():
        all_permission_names_list.update(resource_type_dico[service_type].permission_names)
    return all_permission_names_list


def find_children_by_name(name, parent_id, db_session):
    tree_struct = resource_tree_service.from_parent_deeper(parent_id=parent_id, limit_depth=1, db_session=db_session)
    child_found = node.Resource if name in [node.Resource.resource_name for node in tree_struct] else None
    return child_found


