
from magpie import *
from magpie import models
import transaction
import logging

LOGGER = logging.getLogger(__name__)



def register_user_with_group(user_name, group_name, email, password, db_session):
    db = db_session
    if not GroupService.by_group_name(group_name, db_session=db):
        new_group = models.Group(group_name=group_name)
        db.add(new_group)

    if not UserService.by_user_name(user_name, db_session=db):
        new_user = models.User(user_name=user_name, email=email)
        new_user.set_password(password)
        new_user.regenerate_security_code()
        db.add(new_user)

        group_id = GroupService.by_group_name(user_name, db_session=db).id
        user_id = UserService.by_user_name(user_name, db_session=db).id
        group_entry = models.UserGroup(group_id=group_id, user_id=user_id)
        db.add(group_entry)
    else:
        LOGGER.debug(user_name+' already exist')


def init_anonymous(db_session):
    register_user_with_group(user_name=ANONYMOUS_USER,
                             group_name=ANONYMOUS_USER,
                             email=ANONYMOUS_USER+'@mail.com',
                             password=ANONYMOUS_USER,
                             db_session=db_session)


def init_admin(db_session):
    if not (UserService.by_user_name(ADMIN_USER, db_session=db_session)
            and GroupService.by_group_name(ADMIN_GROUP, db_session=db_session)):
        register_user_with_group(user_name=ADMIN_USER,
                                 group_name=ADMIN_GROUP,
                                 email=ADMIN_USER + '@mail.com',
                                 password=ADMIN_PASSWORD,
                                 db_session=db_session)

    # Check if ADMIN_GROUP has permission ADMIN_PERM
    admin_group = GroupService.by_group_name(ADMIN_GROUP, db_session=db_session)
    permission_names = [permission.perm_name for permission in admin_group.permissions]
    if ADMIN_PERM not in permission_names:
        new_group_permission = models.GroupPermission(perm_name=ADMIN_PERM, group_id=admin_group.id)
        try:
            db_session.add(new_group_permission)
        except Exception, e:
            db_session.rollback()
            raise e



def init_user_group(db_session):
    db = db_session
    if not GroupService.by_group_name(USER_GROUP, db_session=db):
        admin_group = models.Group(group_name=USER_GROUP)
        db.add(admin_group)
    else:
        LOGGER.debug('group USER already initialized')



import time
from magpie.db import get_tm_session, get_session_factory, get_engine, is_database_ready

if __name__ == '__main__':
    # Initialize database with default user: admin+anonymous
    if not is_database_ready():
        time.sleep(2)
        raise Exception('database is not ready yet')
    import ConfigParser
    Config = ConfigParser.ConfigParser()
    curr_dir = os.path.dirname(__file__)
    Config.read(curr_dir+'/magpie/magpie.ini')
    settings = dict(Config.items('app:main'))
    session_factory = get_session_factory(get_engine(settings))
    db_session = get_tm_session(session_factory, transaction)

    init_admin(db_session)
    init_anonymous(db_session)
    init_user_group(db_session)
    transaction.commit()
    db_session.close()

