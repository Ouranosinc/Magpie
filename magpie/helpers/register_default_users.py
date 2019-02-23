from magpie import constants, db, models
from magpie.common import print_log, raise_log, get_logger
from magpie.definitions.sqlalchemy_definitions import Session
from magpie.definitions.ziggurat_definitions import GroupService, UserService
from typing import TYPE_CHECKING
import transaction
import logging
import time
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Optional  # noqa: F401
LOGGER = get_logger(__name__)
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Optional


def register_user_with_group(user_name, group_name, email, password, db_session):
    if not GroupService.by_group_name(group_name, db_session=db_session):
        # noinspection PyArgumentList
        new_group = models.Group(group_name=group_name)
        db_session.add(new_group)
    registered_group = GroupService.by_group_name(group_name=group_name, db_session=db_session)

    registered_user = UserService.by_user_name(user_name, db_session=db_session)
    if not registered_user:
        # noinspection PyArgumentList
        new_user = models.User(user_name=user_name, email=email)
        UserService.set_password(new_user, password)
        UserService.regenerate_security_code(new_user)
        db_session.add(new_user)
        registered_user = UserService.by_user_name(user_name, db_session=db_session)
    else:
        print_log('User `{}` already exist'.format(user_name), level=logging.DEBUG)

    # noinspection PyBroadException
    try:
        # ensure the reference between user/group exists (user joined the group)
        user_group_refs = models.UserGroup.all(db_session=db_session)
        user_group_refs_tup = [(ref.group_id, ref.user_id) for ref in user_group_refs]
        if (registered_group.id, registered_user.id) not in user_group_refs_tup:
            # noinspection PyArgumentList
            group_entry = models.UserGroup(group_id=registered_group.id, user_id=registered_user.id)
            db_session.add(group_entry)
    except Exception:  # in case reference already exists, avoid duplicate error
        db_session.rollback()


def init_anonymous(db_session):
    register_user_with_group(user_name=constants.MAGPIE_ANONYMOUS_USER,
                             group_name=constants.MAGPIE_ANONYMOUS_GROUP,
                             email=constants.MAGPIE_ANONYMOUS_EMAIL,
                             password=constants.MAGPIE_ANONYMOUS_PASSWORD,
                             db_session=db_session)


def init_admin(db_session):
    if not (UserService.by_user_name(constants.MAGPIE_ADMIN_USER, db_session=db_session) and
            GroupService.by_group_name(constants.MAGPIE_ADMIN_GROUP, db_session=db_session)):
        register_user_with_group(user_name=constants.MAGPIE_ADMIN_USER,
                                 group_name=constants.MAGPIE_ADMIN_GROUP,
                                 email=constants.MAGPIE_ADMIN_EMAIL,
                                 password=constants.MAGPIE_ADMIN_PASSWORD,
                                 db_session=db_session)

    # Check if MAGPIE_ADMIN_GROUP has permission MAGPIE_ADMIN_PERMISSION
    magpie_admin_group = GroupService.by_group_name(constants.MAGPIE_ADMIN_GROUP, db_session=db_session)
    permission_names = [permission.perm_name for permission in magpie_admin_group.permissions]
    if constants.MAGPIE_ADMIN_PERMISSION not in permission_names:
        # noinspection PyArgumentList
        new_group_permission = models.GroupPermission(perm_name=constants.MAGPIE_ADMIN_PERMISSION,
                                                      group_id=magpie_admin_group.id)
        try:
            db_session.add(new_group_permission)
        except Exception as e:
            db_session.rollback()
            raise_log('Failed to create admin user-group permission', exception=type(e))


def init_user_group(db_session):
    if not GroupService.by_group_name(constants.MAGPIE_USERS_GROUP, db_session=db_session):
        # noinspection PyArgumentList
        user_group = models.Group(group_name=constants.MAGPIE_USERS_GROUP)
        db_session.add(user_group)
    else:
        print_log('MAGPIE_USERS_GROUP already initialized', level=logging.DEBUG)


def register_default_users(db_session=None):
    # type: (Optional[Session]) -> None
    if not isinstance(db_session, Session):
        db_session = db.get_db_session_from_config_ini(constants.MAGPIE_INI_FILE_PATH)
    if not db.is_database_ready(db_session):
        time.sleep(2)
        raise_log('Database not ready')

    init_admin(db_session)
    init_anonymous(db_session)
    init_user_group(db_session)
    transaction.commit()
    db_session.close()


if __name__ == '__main__':
    register_default_users()
