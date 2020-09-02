"""
remove obsolete personal groups.

Revision ID: 5e7b5346c330
Revises: 2a6c63397399
Create Date: 2018-05-29 16:04:20.724597
"""

import os
import sys

from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm import sessionmaker
from ziggurat_foundations.models.group import GroupMixin
from ziggurat_foundations.models.group_resource_permission import GroupResourcePermissionMixin
from ziggurat_foundations.models.services import BaseService
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.models.user import UserMixin
from ziggurat_foundations.models.user_group import UserGroupMixin
from ziggurat_foundations.models.user_resource_permission import UserResourcePermissionMixin

cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)    # version
root_dir = os.path.dirname(root_dir)    # alembic
root_dir = os.path.dirname(root_dir)    # magpie
root_dir = os.path.dirname(root_dir)    # root
sys.path.insert(0, root_dir)

from magpie.constants import get_constant  # isort:skip # noqa: E402

Session = sessionmaker()

# revision identifiers, used by Alembic.
revision = "5e7b5346c330"
down_revision = "2a6c63397399"
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())
    if isinstance(context.connection.engine.dialect, PGDialect):
        all_users = BaseService.all(UserMixin, db_session=session)
        all_groups = BaseService.all(GroupMixin, db_session=session)
        all_user_group_refs = BaseService.all(UserGroupMixin, db_session=session)
        all_grp_res_perms = BaseService.all(GroupResourcePermissionMixin, db_session=session)

        ignore_groups = {
            get_constant("MAGPIE_ADMIN_GROUP"),
            get_constant("MAGPIE_USERS_GROUP"),
            get_constant("MAGPIE_ANONYMOUS_GROUP")
        }
        user_names = {usr.user_name for usr in all_users}

        # parse through 'personal' groups matching an existing user
        for group in all_groups:
            group_name = group.group_name
            if group_name in user_names and group_name not in ignore_groups:

                # get the real user
                user = UserService.by_user_name(user_name=group_name, db_session=session)

                # transfer permissions from 'personal' group to user
                user_group_res_perm = [urp for urp in all_grp_res_perms if urp.group_id == group.id]
                for group_perm in user_group_res_perm:
                    user_perm = UserResourcePermissionMixin(resource_id=group_perm.resource_id,
                                                            user_id=user.id, perm_name=group_perm.perm_name)  # noqa
                    session.add(user_perm)
                    session.delete(group_perm)

                # delete obsolete personal group and corresponding user-group references
                for usr_grp in all_user_group_refs:
                    if usr_grp.group_id == group.id:
                        session.delete(usr_grp)
                session.delete(group)

        session.commit()


def downgrade():
    pass
