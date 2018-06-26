"""tranfer group users-admins users

Revision ID: ae1a3c8c7860
Revises: 5e7b5346c330
Create Date: 2018-05-30 15:15:33.008614

"""
import os, sys
cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)    # version
root_dir = os.path.dirname(root_dir)    # alembic
root_dir = os.path.dirname(root_dir)    # magpie
root_dir = os.path.dirname(root_dir)    # root
sys.path.insert(0, root_dir)

from alembic import op
from alembic.context import get_context
from definitions.sqlalchemy_definitions import *
from magpie import models, ANONYMOUS_USER
from definitions.ziggurat_definitions import *

Session = sessionmaker()

# OLD/NEW values must be different
OLD_GROUP_USERS = 'user'
NEW_GROUP_USERS = 'users'
OLD_GROUP_ADMIN = 'admin'
NEW_GROUP_ADMIN = 'administrators'

# revision identifiers, used by Alembic.
revision = 'ae1a3c8c7860'
down_revision = '5e7b5346c330'
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())

    # two following lines avoids double 'DELETE' erroneous call when deleting group due to incorrect checks
    # https://stackoverflow.com/questions/28824401/sqlalchemy-attempting-to-twice-delete-many-to-many-secondary-relationship
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    if isinstance(context.connection.engine.dialect, PGDialect):
        all_groups = session.query(models.Group)
        all_user_group_refs = models.UserGroup.all(db_session=session)
        map_groups = {OLD_GROUP_ADMIN: NEW_GROUP_ADMIN, OLD_GROUP_USERS: NEW_GROUP_USERS}

        for group in all_groups:
            if group.group_name in map_groups.keys():
                new_group_name = map_groups[group.group_name]
                new_group = GroupService.by_group_name(new_group_name, db_session=session)

                # create new group if missing
                if not new_group:
                    new_group = models.Group(group_name=new_group_name)
                    session.add(new_group)
                    new_group = GroupService.by_group_name(new_group_name, db_session=session)

                old_group_perms = GroupService.resources_with_possible_perms(group, db_session=session)
                new_group_perms = GroupService.resources_with_possible_perms(new_group, db_session=session)
                diff_group_perms = set(old_group_perms) - set(new_group_perms)

                for perm in diff_group_perms:
                    perm.group = new_group
                    session.add(perm)

                for perm in old_group_perms:
                    session.delete(perm)

                old_group_users = [user.user_name for user in group.users]
                new_group_users = [user.user_name for user in new_group.users]
                diff_group_users = set(old_group_users) - set(new_group_users)

                for user_name in diff_group_users:
                    user = UserService.by_user_name(user_name=user_name, db_session=session)
                    user_group = models.UserGroup(group_id=new_group.id, user_id=user.id)
                    session.add(user_group)

                session.delete(group)
                for user_group in all_user_group_refs:
                    if user_group.group_id == group.id:
                        session.delete(user_group)

        # remove anonymous group references
        anonymous_group = GroupService.by_group_name(group_name=ANONYMOUS_USER, db_session=session)
        if anonymous_group:
            for user_group in all_user_group_refs:
                if user_group.group_id == anonymous_group.id:
                    session.delete(user_group)
            session.delete(anonymous_group)

        session.commit()


def downgrade():
    pass
