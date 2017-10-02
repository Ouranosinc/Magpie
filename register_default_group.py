
from magpie import *
from magpie import models
import transaction
import logging

LOGGER = logging.getLogger(__name__)




def init_anonymous(db_session):
    db = db_session
    if not GroupService.by_group_name(ANONYMOUS_USER, db_session=db):
        anonymous_group = models.Group(group_name=ANONYMOUS_USER)
        db.add(anonymous_group)

    if not UserService.by_user_name(ANONYMOUS_USER, db_session=db):
        anonymous_user = models.User(user_name=ANONYMOUS_USER, email=ANONYMOUS_USER + '@mail.com')
        db.add(anonymous_user)

        group_id = GroupService.by_group_name(ANONYMOUS_USER, db_session=db).id
        user_id = UserService.by_user_name(ANONYMOUS_USER, db_session=db).id
        group_entry = models.UserGroup(group_id=group_id, user_id=user_id)
        db.add(group_entry)

    else:
        LOGGER.debug('anonymous already initialized')


def init_admin(db_session):
    db = db_session
    if not GroupService.by_group_name(ADMIN_GROUP, db_session=db):
        admin_group = models.Group(group_name=ADMIN_GROUP)
        db.add(admin_group)

    if not UserService.by_user_name(ADMIN_USER, db_session=db):
        admin_user = models.User(user_name=ADMIN_USER, email=ADMIN_USER + '@mail.com')
        admin_user.set_password(ADMIN_PASSWORD)
        admin_user.regenerate_security_code()
        db.add(admin_user)

        group = GroupService.by_group_name(ADMIN_GROUP, db_session=db)
        admin = UserService.by_user_name(ADMIN_USER, db_session=db)

        group_entry = models.UserGroup(group_id=group.id, user_id=admin.id)
        db.add(group_entry)

        new_group_permission = models.GroupPermission(perm_name=ADMIN_PERM, group_id=group.id)
        db.add(new_group_permission)

    else:
        LOGGER.debug('admin already initialized')


def init_user(db_session):
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
    init_user(db_session)
    transaction.commit()
    db_session.close()

