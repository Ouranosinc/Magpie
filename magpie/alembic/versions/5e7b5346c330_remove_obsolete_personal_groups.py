"""remove obsolete personal groups

Revision ID: 5e7b5346c330
Revises: 2a6c63397399
Create Date: 2018-05-29 16:04:20.724597

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
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm import sessionmaker
from magpie import models, ANONYMOUS_USER, ADMIN_GROUP, USER_GROUP
from ziggurat_definitions import *

Session = sessionmaker()

# revision identifiers, used by Alembic.
revision = '5e7b5346c330'
down_revision = '2a6c63397399'
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())
    if isinstance(context.connection.engine.dialect, PGDialect):
        all_users = session.query(models.User)
        all_groups = session.query(models.Group)
        all_user_group_refs = models.UserGroup.all(db_session=session)

        ignore_groups = {ADMIN_GROUP, USER_GROUP}
        user_names = {usr.user_name for usr in all_users}

        # parse through 'personal' groups matching an existing user
        for group in all_groups:
            group_name = group.group_name
            if group_name in user_names and group_name not in ignore_groups:

                # get the real user
                user = UserService.by_user_name(user_name=group_name, db_session=session)

                # transfer permissions from 'personal' group to user
                user_perms = GroupService.resources_with_possible_perms(group, db_session=session)
                for perm in user_perms:
                    new_perm = models.UserResourcePermission(resource_id=perm.resource.resource_id, user_id=user.id)
                    new_perm.perm_name = perm.perm_name
                    session.add(new_perm)

                # delete obsolete 'personal' group permissions
                for perm in group.resource_permissions:
                    session.delete(perm)

                # delete obsolete personal group and corresponding user-group references
                for usr_grp in all_user_group_refs:
                    if usr_grp.group_id == group.id:
                        session.delete(usr_grp)
                session.delete(group)

        session.commit()


def downgrade():
    pass
