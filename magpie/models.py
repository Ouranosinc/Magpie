import datetime
import math
import uuid
from typing import TYPE_CHECKING

import sqlalchemy as sa
from pyramid.httpexceptions import HTTPForbidden, HTTPInternalServerError, HTTPNotFound
from pyramid.security import ALL_PERMISSIONS, Allow, Authenticated, Everyone
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship
from ziggurat_foundations import ziggurat_model_init
from ziggurat_foundations.models.base import BaseModel, get_db_session
from ziggurat_foundations.models.external_identity import ExternalIdentityMixin
from ziggurat_foundations.models.group import GroupMixin
from ziggurat_foundations.models.group_permission import GroupPermissionMixin
from ziggurat_foundations.models.group_resource_permission import GroupResourcePermissionMixin
from ziggurat_foundations.models.resource import ResourceMixin
from ziggurat_foundations.models.services import BaseService
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource_tree import ResourceTreeService
from ziggurat_foundations.models.services.resource_tree_postgres import ResourceTreeServicePostgreSQL
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.models.user import UserMixin
from ziggurat_foundations.models.user_group import UserGroupMixin
from ziggurat_foundations.models.user_permission import UserPermissionMixin
from ziggurat_foundations.models.user_resource_permission import UserResourcePermissionMixin
from ziggurat_foundations.permissions import permission_to_pyramid_acls

from magpie.api import exception as ax
from magpie.constants import get_constant
from magpie.permissions import Permission
from magpie.utils import ExtendedEnum, FlexibleNameEnum, decompose_enum_flags, get_logger, get_magpie_url

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, Iterable, List, Optional, Set, Type, Union

    from sqlalchemy.orm.query import Query
    from sqlalchemy.orm.session import Session

    from magpie.typedefs import JSON, AccessControlListType, GroupPriority, Str

    # for convenience of methods using both, using strings because of future definition
    AnyUser = Union["User", "UserPending"]

# backward compat enums
try:
    from enum import IntFlag
except ImportError:  # python < 3.6
    from aenum import IntFlag  # noqa

LOGGER = get_logger(__name__)

Base = declarative_base()   # pylint: disable=C0103,invalid-name


def get_session_callable(request):
    return request.db


class Group(GroupMixin, Base):
    _priority = None

    def get_member_count(self, db_session=None):
        return BaseService.all(UserGroup, db_session=db_session).filter(UserGroup.group_id == self.id).count()

    @declared_attr
    def discoverable(self):
        """
        Indicates if the group is discoverable for users to self-register to it.
        """
        return sa.Column(sa.Boolean(), default=False)

    @declared_attr
    def terms(self):
        """
        Text containing the terms and conditions.
        """
        return sa.Column(sa.UnicodeText(), nullable=True)

    @property
    def priority(self):
        # type: () -> GroupPriority
        """
        Sorting priority weight of the group for resolving conflicting permissions.
        """
        if self._priority is not None:
            return self._priority
        if self.group_name == get_constant("MAGPIE_ANONYMOUS_GROUP"):
            self._priority = -1  # lowest of all for *special* public group
        elif self.group_name == get_constant("MAGPIE_ADMIN_GROUP"):
            self._priority = math.inf  # everything will be lower than admins
        else:
            self._priority = 0  # nothing can be lower/equal to anonymous, equal for any *generic* group
        return self._priority


class GroupPermission(GroupPermissionMixin, Base):
    pass


class UserGroupStatus(FlexibleNameEnum):
    """
    Supported statuses of user-group relationships.
    """
    ALL = "all"
    ACTIVE = "active"
    PENDING = "pending"

    @classmethod
    def allowed(cls):
        # type: () -> List[Str]
        """
        Returns all supported representation values that can be mapped to a valid status.
        """
        names = cls.names()
        allowed = names
        allowed.extend([name.lower() for name in names])
        return allowed


class UserGroup(UserGroupMixin, Base):
    pass


class GroupResourcePermission(GroupResourcePermissionMixin, Base):
    pass


class Resource(ResourceMixin, Base):
    # required resource type identifier (unique)
    resource_type_name = None       # type: Str
    permissions = []                # type: List[Permission]
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
        # type: () -> AccessControlListType
        """
        User or group that owns a resource are granted full access to it.
        """
        acl = []
        if self.owner_user_id:
            acl.append((Allow, self.owner_user_id, ALL_PERMISSIONS))
        if self.owner_group_id:
            acl.append((Allow, "group:%s" % self.owner_group_id, ALL_PERMISSIONS))
        return acl

    def __str__(self):
        return "<Resource: name={} type={} id={}>".format(self.resource_name, self.resource_type, self.resource_id)


class UserPermission(UserPermissionMixin, Base):
    pass


class UserResourcePermission(UserResourcePermissionMixin, Base):
    pass


class User(UserMixin, Base):
    def __str__(self):
        return "<User: name={} id={}>".format(self.user_name, self.id)

    def get_groups_by_status(self, status, db_session=None):
        # type: (UserGroupStatus, Session) -> Set[Str]
        """
        List all groups a user belongs to, filtered by UserGroup status type.
        """
        from magpie.api.management.user.user_utils import get_user_groups_checked

        cur_session = get_db_session(session=db_session) if db_session else get_db_session(obj=self)

        group_names = set()
        member_group_names = set(get_user_groups_checked(self, cur_session))
        if status in [UserGroupStatus.ACTIVE, UserGroupStatus.ALL]:
            group_names = group_names.union(member_group_names)
        if status in [UserGroupStatus.PENDING, UserGroupStatus.ALL]:
            tmp_tokens = TemporaryToken.by_user(self).filter(
                TemporaryToken.operation == TokenOperation.GROUP_ACCEPT_TERMS)
            pending_group_names = set(tmp_token.group.group_name for tmp_token in tmp_tokens)

            # Remove any group a user already belongs to, in case any tokens are irrelevant.
            # Should not happen since related tokens are deleted upon T&C acceptation.
            pending_group_names = pending_group_names - member_group_names
            group_names = group_names.union(pending_group_names)
        return group_names


class UserPending(Base):
    """
    Temporary definition of a :class:`User` pending for approval by an administrator.
    """

    @declared_attr
    def __tablename__(self):
        return "users_pending"

    @declared_attr
    def id(self):  # pylint: disable=C0103,invalid-name  # considered too short
        """
        Unique identifier of user.
        """
        return sa.Column(sa.Integer, primary_key=True, autoincrement=True)

    @declared_attr
    def user_name(self):
        """
        Unique user name.
        """
        return sa.Column(sa.Unicode(128), nullable=False, unique=True)

    @declared_attr
    def user_password(self):
        """
        Password hash of the user.
        """
        return sa.Column(sa.Unicode(256), nullable=False)

    @declared_attr
    def email(self):
        """
        Email of the user.
        """
        return sa.Column(sa.Unicode(100), nullable=False, unique=True)

    @declared_attr
    def registered_date(self):
        """
        Date of user's registration.
        """
        return sa.Column(sa.TIMESTAMP(timezone=False), default=datetime.datetime.utcnow, server_default=sa.func.now())

    @property
    def status(self):
        """
        Pending user status is enforced.

        Avoid error in case the corresponding attribute of :class:`User` was accessed.
        """
        return UserStatuses.Pending.value

    @property
    def groups(self):
        """
        Pending user is not a member of any group.

        Avoid error in case this field gets accessed when simultaneously handling :class:`User` and :class`UserPending`.
        """
        return []

    def get_groups_by_status(self, status, db_session=None):
        """
        Pending user is not a member of any group.

        Avoid error in case this method gets accessed when simultaneously
        handling :class:`User` and :class`UserPending`.
        """
        return []

    def upgrade(self, db_session=None):
        # type: (Optional[Session]) -> User
        """
        Upgrades this :class`UserPending` instance to a complete and corresponding :class:`User` definition.

        Automatically handles instance updates in the database.
        All relevant :class:`User` metadata is transferred from available :class:`UserPending` details.

        All operations that should take place during normal :class:`User` creation will take effect, including minimal
        :class:`Group` membership creation and :term:`Webhook` triggers.

        This current :class:`UserPending` instance is finally removed and should not be accessed following upgrade.

        :param db_session: Database connection to use, otherwise retrieved from the user pending object.
        :returns: created user instance
        """
        # employ the typical user creation utility to ensure that all webhooks and validations occur as usual
        # avoid circular import errors
        from magpie.api.management.user.user_utils import create_user
        from magpie.db import get_session_from_other

        # Because create user operation closes session to commit the user and allow webhook updating it,
        # retrieve another session to complete upgrade and remove the pending user in advance.
        cur_session = get_db_session(session=db_session) if db_session else get_db_session(obj=self)
        tmp_session = get_session_from_other(cur_session)
        create_user(self.user_name, email=self.email, db_session=tmp_session,
                    group_name=None, registered_date=self.registered_date,
                    # Since password was already hashed during pending user creation,
                    # and that we cannot decrypt the raw one, transfer the hash directly.
                    user_password=self.user_password, password=None)

        # if nothing was raised, user should have been created (possibly with webhook error, but not an issue to resume)
        # retrieve the detached pending user from session caused by other transaction closed and delete it
        pending_user = cur_session.merge(self) if sa.inspect(self).detached else self
        cur_session.delete(pending_user)
        # make sure all changes were committed so that the current session can retrieve the new user
        tmp_session.commit()
        tmp_session.close()
        user = UserService.by_user_name(pending_user.user_name, db_session=cur_session)
        return user

    @property
    def passwordmanager(self):
        """
        Employ the same password manager attached to :class:`User` instances from :class:`UserService`.

        This allows all functionalities of password generation, encryption and comparison to be directly transferable
        between this pending user until it eventually gets upgraded to a full :class:`User` once validated.
        """
        return UserService.model.passwordmanager


class UserStatuses(IntFlag, FlexibleNameEnum):
    """
    Values applicable to :term:`User` statues.

    Provides allowed values for the ``status`` search query of :class:`User` and :class:`UserPending` entries.
    Also, defines the possible values of :attr:`User.status` field, omitting :attr:`UserStatuses.Pending` reserved
    for objects defined by :class:`UserPending`.
    """
    # pylint: disable=W0221,arguments-differ,C0103,invalid-name

    # 0: do not use (reserved for no set flag)
    OK = 1  # use 1 for ok since this value is set by default by ziggurat
    WebhookError = 2
    Pending = 4

    @classmethod
    def _get_one(cls, status):
        # matches the literal number, the direct enum object, exact name, or flexible name (inherited)
        status = super(UserStatuses, cls).get(int(status) if str.isnumeric(str(status)) else status)
        if status:
            # always convert as enum instance to allow flag combinations (|) and membership compare (in)
            return UserStatuses(status)
        return None

    @classmethod
    def get(cls,
            status,         # type: Union[None, int, Str, UserStatuses, Iterable[None, int, Str, UserStatuses]]
            default=None,   # type: Optional[UserStatuses]
            ):              # type: (...) -> Optional[UserStatuses]
        """
        Obtains the combined flag :class:`UserStatuses`
        """
        if status is None:
            return default
        if status in ["all", "All", "ALL"]:
            return cls.all()
        if isinstance(status, str) and "," in status:
            status = status.split(",")
        if isinstance(status, (str, int)):
            return cls._get_one(status)
        combined = None
        for _status in status:
            _status = cls._get_one(_status)
            if combined is not None and _status is not None:
                combined = (combined | _status)
            else:
                combined = combined or _status
        return UserStatuses(combined)

    @classmethod
    def allowed(cls):
        # type: () -> List[Union[None, int, Str]]
        """
        Returns all supported representation values that can be mapped to a valid status for :class:`UserSearchService`.
        """
        allowed = cls.values()  # literal int
        allowed.extend(list(str(status) for status in allowed))  # by str repr of int value
        names = cls.names()
        allowed.extend(names)  # by literal name of status
        allowed.extend([name.upper() for name in names])
        allowed.extend([name.lower() for name in names])
        allowed.extend([None, "all", "All", "ALL"])  # unspecified (valid users omit pending) or literally 'all' users
        return allowed

    @classmethod
    def all(cls):
        """
        Representation of all flags combined.
        """
        return UserStatuses(sum(cls.values()))

    # nothing to do, only improve typing to avoid complaints about expecting 'int'
    def __or__(self, other):  # type: (Union[UserStatuses, int]) -> UserStatuses
        return super(UserStatuses, self).__or__(other)

    # nothing to do, only improve typing to avoid complaints about expecting 'int'
    def __and__(self, other):  # type: (Union[UserStatuses, int]) -> UserStatuses
        return super(UserStatuses, self).__and__(other)

    # nothing to do, only improve typing to avoid complaints about expecting 'int'
    def __xor__(self, other):  # type: (Union[UserStatuses, int]) -> UserStatuses
        return super(UserStatuses, self).__xor__(other)

    def __iter__(self):
        values = decompose_enum_flags(self)
        return iter(values)

    def __len__(self):
        # use literal to avoid recursion
        count = 0
        value = self.value
        while value:
            value &= (value - 1)
            count += 1
        return count


class UserSearchService(UserService):
    """
    Extends the :mod:`ziggurat_foundations` :class:`UserService` with additional features provided by `Magpie`.

    .. note::
        For any search result where parameter ``status`` is equal to or contains :attr:`UserStatuses.Pending` combined
        with any other :class:`UserStatuses` members, or through the *all* representation, the returned iterable could
        be a mix of both :term:`User` models or only :class:`UserPending`. Therefore, only fields supported by both of
        those models should be accessed from the result.
    """

    @classmethod
    def by_status(cls, status=None, db_session=None):
        # type: (Optional[UserStatuses], Optional[Session]) -> Iterable[AnyUser]
        """
        Search for appropriate :class:`User` and/or :class:`UserPending` according to specified :class:`UserStatuses`.

        When the :paramref:`status` is ``None``, *normal* retrieval of all non-pending :class:`User` is executed, as if
        directly using the :class:`UserService` implementation.
        Otherwise, a combination of appropriate search criterion is executed based on the :paramref:`status` flags.
        """
        db_session = get_db_session(db_session)
        if status is UserStatuses.Pending:
            return db_session.query(UserPending)
        if status is None:
            # original behavior, all approved users returned regardless of statuses, ignoring pending ones
            return db_session.query(cls.model)
        query = db_session.query(cls.model)
        users = []  # must combine by list since different models will clash in query
        if UserStatuses.Pending in status:
            users = list(db_session.query(UserPending))
            status = UserStatuses(status - UserStatuses.Pending)
        status = [int(status_flag) for status_flag in status]
        query = query.filter(cls.model.status.in_(status))
        users += list(query)
        return users

    @classmethod
    def by_user_name(cls, user_name, status=None, db_session=None):  # pylint: disable=W0221,arguments-differ
        # type: (Str, Optional[UserStatuses], Optional[Session]) -> Optional[AnyUser]
        """
        Retrieves the user matching the given name.

        Search is always accomplished against :class:`User` table unless :attr:`UserStatuses.Pending` is provided in
        the :paramref:`status`. If more that one status is provided such that both :class:`UserPending` and
        :class:`User` could yield results, the :class:`User` is returned first, as there should not be any conflict
        between those two models.
        """
        if status is None or UserStatuses.Pending not in status:
            return super(UserSearchService, cls).by_user_name(user_name, db_session=db_session)
        users = list(cls.by_status(status=status, db_session=db_session))
        if not users:
            return None
        users = [user for user in users if user.user_name == user_name]
        if not users:
            return None
        if len(users) == 1:
            return users[0]
        LOGGER.warning("Duplicate registered/pending users named [%s] detected! This should never happen.", user_name)
        return users[0] if isinstance(users[0], User) else users[1]

    @classmethod
    def by_name_or_email(cls, user_name, email, status=None, db_session=None):
        # type: (Str, Str, Optional[UserStatuses], Optional[Session]) -> Optional[AnyUser]
        """
        Retrieves the first matched user by either name or email, whichever comes first.

        If the :paramref:`status` is provided, search is executed against relevant :class:`User` and/or
        :class`UserPending` definitions. The :paramref:`user_name` is looked for first across both tables (as needed)
        and then by :paramref:`email` if not previously matched.

        .. seealso::
            :meth:`by_user_name`
            :meth:`by_email`
            :meth:`by_email_and_username`
        """
        db_session = get_db_session(db_session)
        if status is None or UserStatuses.Pending not in status:
            query = db_session.query(cls.model)
            if status is not None:
                status = [int(status) for status in status]
                query = query.in_(status)
            return query.filter((User.user_name == user_name) | (User.email == email)).first()
        user = cls.by_user_name(user_name=user_name, status=status, db_session=db_session)
        if user is not None:
            return user
        if status is UserStatuses.Pending:
            return db_session.query(UserPending).filter(UserPending.email == email).first()
        user = super(UserSearchService, cls).by_email(email=email, db_session=db_session)
        if user is not None and UserStatuses.get(user.status) in status:
            return user
        return db_session.query(UserPending).filter(UserPending.email == email).first()


class ExternalIdentity(ExternalIdentityMixin, Base):
    pass


class RootFactory(object):
    """
    Used to build base Access Control List (ACL) of the request user.

    All API and UI routes will employ this set of effective principals to determine if the user is authorized to access
    the pyramid view according to the ``permission`` value it was configured with.

    .. note::
        Keep in mind that `Magpie` is configured with default permission
        :py:data:`magpie.constants.MAGPIE_ADMIN_PERMISSION`.
        Views that require more permissive authorization must be overridden with ``permission`` argument.

    .. seealso::
        - ``set_default_permission`` within :func:`magpie.includeme` initialization steps
    """
    __name__ = None
    __parent__ = ""

    def __init__(self, request):
        self.request = request

    @property
    def __acl__(self):
        # type: () -> AccessControlListType
        """
        Administrators have all permissions, user/group-specific permissions added if user is logged in.
        """
        user = self.request.user
        # allow if role MAGPIE_ADMIN_PERMISSION is somehow directly set instead of inferred via members of admin-group
        acl = [(Allow, get_constant("MAGPIE_ADMIN_PERMISSION", self.request), ALL_PERMISSIONS)]
        admin_group_name = get_constant("MAGPIE_ADMIN_GROUP", self.request)
        admins = GroupService.by_group_name(admin_group_name, db_session=self.request.db)
        if admins:
            # need to add explicit admin-group ALL_PERMISSIONS otherwise views with other permissions than the
            # default MAGPIE_ADMIN_PERMISSION will be refused access (e.g.: views with MAGPIE_LOGGED_PERMISSION)
            acl += [(Allow, "group:{}".format(admins.id), ALL_PERMISSIONS)]
        if user:
            # user-specific permissions (including group memberships)
            permissions = UserService.permissions(user, self.request.db)
            user_acl = permission_to_pyramid_acls(permissions)
            # allow views that require minimally to be logged in (regardless of who is the user)
            auth_acl = [(Allow, user.id, Authenticated)]
            acl += user_acl + auth_acl
        return acl


class UserFactory(RootFactory):
    def __init__(self, request):
        super(UserFactory, self).__init__(request)
        self.path_user = None

    def __getitem__(self, user_name):
        context = UserFactory(self.request)
        if user_name == get_constant("MAGPIE_LOGGED_USER", self.request):
            self.path_user = self.request.user
        else:
            self.path_user = UserService.by_user_name(user_name, self.request.db)
        if self.path_user is not None:
            self.path_user.__parent__ = self
            self.path_user.__name__ = user_name
        context.path_user = self.path_user
        return context

    @property
    def __acl__(self):
        # type: () -> AccessControlListType
        """
        Grant access to :term:`Request User` according to its relationship to :term:`Context User`.

        If it is the same user (either from explicit name or by :py:data:`magpie.constants.MAGPIE_LOGGED_USER` reserved
        keyword), allow :py:data:`magpie.constants.MAGPIE_LOGGED_PERMISSION` for itself to access corresponding views.

        If request user is unauthenticated (``None``), :py:data:`magpie.constants.MAGPIE_LOGGED_USER` or itself,
        also grant :py:data:`magpie.constants.MAGPIE_CONTEXT_PERMISSION` to allow access to contextually-available
        details (e.g.: user can view his own information and public ones).

        All ACL permissions from :class:`RootFactory` are applied on top of user-specific permissions added here.
        """
        user = self.request.user
        acl = super(UserFactory, self).__acl__   # inherit default permissions for non user-scoped routes
        # when user is authenticated and refers to itself, simultaneously fulfill both logged/context conditions
        if user and self.path_user and user.id == self.path_user.id:
            acl += [(Allow, user.id, get_constant("MAGPIE_LOGGED_PERMISSION")),
                    (Allow, user.id, get_constant("MAGPIE_CONTEXT_PERMISSION"))]
        # unauthenticated context is allowed if and only if referring also to the unauthenticated user
        elif user is None:
            if self.path_user is None or self.path_user.user_name == get_constant("MAGPIE_ANONYMOUS_USER"):
                acl += [(Allow, Everyone, get_constant("MAGPIE_CONTEXT_PERMISSION"))]
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
    __mapper_args__ = {
        "polymorphic_identity": resource_type_name,
        "inherit_condition": resource_id == Resource.resource_id
    }

    @property
    def permissions(self):  # pragma: no cover
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

    @declared_attr
    def configuration(self):
        """
        Configuration modifiers for parsing access to resources and permissions.

        .. seealso::
            - :meth:`magpie.services.ServiceInterface.get_config`
        """
        return sa.Column(sa.JSON(), nullable=True)

    @staticmethod
    def by_service_name(service_name, db_session):
        session = get_db_session(db_session)
        service = session.query(Service).filter(Resource.resource_name == service_name).first()
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
        Permission.READ,
        Permission.WRITE,
    ]


class Process(Resource):
    child_resource_allowed = False
    resource_type_name = "process"
    __mapper_args__ = {"polymorphic_identity": resource_type_name}

    permissions = [
        Permission.DESCRIBE_PROCESS,
        Permission.EXECUTE,
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
    def __init__(self, service_cls):
        self.model = RemoteResource
        super(RemoteResourceTreeServicePostgresSQL, self).__init__(service_cls)

    # FIXME: https://github.com/ergo/ziggurat_foundations/pull/70
    @classmethod
    def build_subtree_strut(cls, result, *args, **kwargs):
        """
        Returns a dictionary in form of ``{node:Resource, children:{node_id: Resource}}``.

        :param result:
        :return:
        """
        items = list(result)
        root_elem = {"node": None, "children": dict()}
        if len(items) == 0:
            return root_elem
        for _, node in enumerate(items):
            node_res = getattr(node, cls.model.__name__)
            new_elem = {"node": node_res, "children": dict()}
            path = list(map(int, node.path.split("/")))
            parent_node = root_elem
            normalized_path = path[:-1]
            if normalized_path:
                for path_part in normalized_path:
                    parent_node = parent_node["children"][path_part]
            parent_node["children"][new_elem["node"].resource_id] = new_elem
        return root_elem


class TokenOperation(ExtendedEnum):
    """
    Supported operations by the temporary tokens.
    """

    GROUP_ACCEPT_TERMS = "group-accept-terms"
    """
    Temporary token associated to an URL endpoint called by an user that accepts the terms and conditions (T&C)
    to join a particular group.
    """

    USER_PASSWORD_RESET = "user-password-reset"  # nosec: B105
    """
    Temporary token associated to an URL endpoint to request a user password reset.
    """

    USER_REGISTRATION_CONFIRM_EMAIL = "user-registration-confirm-email"
    """
    Temporary token associated to a pending user registration that requires email validation by visiting the link.
    """

    USER_REGISTRATION_ADMIN_APPROVE = "user-registration-admin-approve"
    """
    Temporary token associated to a pending user registration that will be approved by an administrator when visited.
    """

    USER_REGISTRATION_ADMIN_DECLINE = "user-registration-admin-decline"
    """
    Temporary token associated to a pending user registration that will be declined by an administrator when visited.
    """

    WEBHOOK_USER_STATUS_ERROR = "webhook-user-status-error"
    """
    Temporary token employed to provide a callback URL that a registered webhook can call following the triggered
    event to indicate that the corresponding operation resulted into an invalid user status.
    """


class TemporaryToken(BaseModel, Base):
    """
    Model that defines a token for temporary URL completion of a given pending operation.
    """
    __tablename__ = "tmp_tokens"

    def __init__(self, *_, **__):
        super(TemporaryToken, self).__init__(*_, **__)
        # auto generate token to avoid manually specifying it when creating instance and directly
        # requesting the temporary URL, while the instance it not yet saved in the database
        if not self.token:
            self.token = self.token = uuid.uuid4()

    token = sa.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True)
    operation = sa.Column(sa.Enum(TokenOperation, name=TokenOperation.__name__, length=32), nullable=False)
    created = sa.Column(sa.DateTime, default=datetime.datetime.utcnow)

    user_id = sa.Column(sa.Integer,
                        sa.ForeignKey("users.id", onupdate="CASCADE", ondelete="CASCADE"),
                        nullable=True)
    _user = relationship("User", foreign_keys=[user_id])
    user_pending_id = sa.Column(sa.Integer,
                                sa.ForeignKey("users_pending.id", onupdate="CASCADE", ondelete="CASCADE"),
                                nullable=True)
    _pending_user = relationship("UserPending", foreign_keys=[user_pending_id])

    group_id = sa.Column(sa.Integer(),
                         sa.ForeignKey("groups.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=True)
    group = relationship("Group", foreign_keys=[group_id])

    @hybrid_property
    def user(self):
        # type: () -> AnyUser
        return self._user or self._pending_user

    @user.setter
    def user(self, user):
        # type: (AnyUser) -> None
        if isinstance(user, User):
            self._user = user
        elif isinstance(user, UserPending):
            self._pending_user = user

    def url(self, settings=None):
        from magpie.api import schemas as s
        return get_magpie_url(settings) + s.TemporaryUrlAPI.path.format(token=self.token)

    def expired(self):
        expire = int(get_constant("MAGPIE_TOKEN_EXPIRE", raise_missing=False, raise_not_set=False, default_value=86400))
        return (datetime.datetime.utcnow() - self.created) > datetime.timedelta(seconds=expire)

    @staticmethod
    def by_token(token, db_session=None):
        # type: (Union[Str, UUID], Optional[Session]) -> Optional[TemporaryToken]
        db_session = get_db_session(db_session)
        return db_session.query(TemporaryToken).filter(TemporaryToken.token == token).first()

    @staticmethod
    def by_user(user, db_session=None):
        # type: (AnyUser, Optional[Session]) -> Optional[Query]
        if not db_session:
            db_session = get_db_session(obj=user)
        query = db_session.query(TemporaryToken)
        if isinstance(user, User):
            query = query.filter(TemporaryToken.user_id == user.id)
        elif isinstance(user, UserPending):
            query = query.filter(TemporaryToken.user_pending_id == user.id)
        else:
            return None
        return query

    def json(self):
        # type: () -> JSON
        return {"token": str(self.token), "operation": str(self.operation.value)}


ziggurat_model_init(User, Group, UserGroup, GroupPermission, UserPermission,
                    UserResourcePermission, GroupResourcePermission, Resource,
                    ExternalIdentity, passwordmanager=None)

RESOURCE_TREE_SERVICE = ResourceTreeService(ResourceTreeServicePostgreSQL)
REMOTE_RESOURCE_TREE_SERVICE = RemoteResourceTreeService(RemoteResourceTreeServicePostgresSQL)

RESOURCE_TYPE_DICT = dict()  # type: Dict[Str, Type[Resource]]
for res in [Service, Directory, File, Workspace, Route, Process]:
    if res.resource_type_name in RESOURCE_TYPE_DICT:  # pragma: no cover
        raise KeyError("Duplicate resource type identifiers not allowed")
    RESOURCE_TYPE_DICT[res.resource_type_name] = res


def resource_factory(**kwargs):
    resource_type = ax.evaluate_call(lambda: kwargs["resource_type"], http_error=HTTPInternalServerError,
                                     msg_on_fail="kwargs do not contain required 'resource_type'",
                                     content={"kwargs": repr(kwargs)})
    msg = "kwargs unpacking failed from specified 'resource_type' and 'RESOURCE_TYPE_DICT'"
    return ax.evaluate_call(lambda: RESOURCE_TYPE_DICT[resource_type](**kwargs),  # noqa
                            http_error=HTTPInternalServerError, msg_on_fail=msg,
                            content={"kwargs": repr(kwargs), "RESOURCE_TYPE_DICT": repr(RESOURCE_TYPE_DICT)})


def find_children_by_name(child_name, parent_id, db_session):
    tree_struct = RESOURCE_TREE_SERVICE.from_parent_deeper(parent_id=parent_id, limit_depth=1, db_session=db_session)
    tree_level_filtered = [node.Resource for node in list(tree_struct) if
                           node.Resource.resource_name.lower() == child_name.lower()]
    return tree_level_filtered.pop() if len(tree_level_filtered) else None
