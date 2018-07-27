from magpie import *
from common import *
from magpie.definitions.ziggurat_definitions import *
import models
import db
import transaction
import logging
import time

LOGGER = logging.getLogger(__name__)


def register_user_with_group(user_name, group_name, email, password, db_session):
    if not GroupService.by_group_name(group_name, db_session=db_session):
        new_group = models.Group(group_name=group_name)
        db_session.add(new_group)
    registered_group = models.Group.by_group_name(group_name=group_name, db_session=db_session)

    registered_user = UserService.by_user_name(user_name, db_session=db_session)
    if not registered_user:
        new_user = models.User(user_name=user_name, email=email)
        new_user.set_password(password)
        new_user.regenerate_security_code()
        db_session.add(new_user)
        registered_user = UserService.by_user_name(user_name, db_session=db_session)
    else:
        print_log(user_name+' already exist', level=logging.DEBUG)

    try:
        # ensure the reference between user/group exists (user joined the group)
        user_group_refs = models.UserGroup.all(db_session=db_session)
        user_group_refs_tup = [(ref.group_id, ref.user_id) for ref in user_group_refs]
        if (registered_group.id, registered_user.id) not in user_group_refs_tup:
            group_entry = models.UserGroup(group_id=registered_group.id, user_id=registered_user.id)
            db_session.add(group_entry)
    except:  # in case reference already exists, avoid duplicate error
        db_session.rollback()


def init_anonymous(db_session):
    register_user_with_group(user_name=ANONYMOUS_USER,
                             group_name=ANONYMOUS_GROUP,
                             email=ANONYMOUS_USER + '@mail.com',
                             password=ANONYMOUS_PASSWORD,
                             db_session=db_session)


def init_admin(db_session):
    if not (UserService.by_user_name(ADMIN_USER, db_session=db_session)
            and GroupService.by_group_name(ADMIN_GROUP, db_session=db_session)):
        register_user_with_group(user_name=ADMIN_USER,
                                 group_name=ADMIN_GROUP,
                                 email=ADMIN_USER + '@mail.com',
                                 password=ADMIN_PASSWORD,
                                 db_session=db_session)

    # Check if ADMIN_GROUP has permission ADMIN_PERMISSION
    admin_group = GroupService.by_group_name(ADMIN_GROUP, db_session=db_session)
    permission_names = [permission.perm_name for permission in admin_group.permissions]
    if ADMIN_PERMISSION not in permission_names:
        new_group_permission = models.GroupPermission(perm_name=ADMIN_PERMISSION, group_id=admin_group.id)
        try:
            db_session.add(new_group_permission)
        except Exception as e:
            db_session.rollback()
            raise_log('Failed to create admin user-group permission', exception=type(e))


def init_user_group(db_session):
    if not GroupService.by_group_name(USERS_GROUP, db_session=db_session):
        user_group = models.Group(group_name=USERS_GROUP)
        db_session.add(user_group)
    else:
        print_log('USERS_GROUP already initialized', level=logging.DEBUG)


def register_default_users():
    if not db.is_database_ready():
        time.sleep(2)
        raise_log('Database not ready')

    db_session = db.get_db_session_from_config_ini(MAGPIE_INI_FILE_PATH)
    init_admin(db_session)
    init_anonymous(db_session)
    init_user_group(db_session)
    transaction.commit()
    db_session.close()


if __name__ == '__main__':
    register_default_users()
