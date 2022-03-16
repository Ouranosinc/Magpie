"""
Remove obsolete personal groups.

Revision ID: 5e7b5346c330
Revises: 2a6c63397399
Create Date: 2018-05-29 16:04:20.724597
"""

import os
import sys

import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm import sessionmaker

cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)    # version
root_dir = os.path.dirname(root_dir)    # alembic
root_dir = os.path.dirname(root_dir)    # magpie
root_dir = os.path.dirname(root_dir)    # root
sys.path.insert(0, root_dir)

from magpie.constants import get_constant  # isort:skip # pylint: disable=C0413 # noqa: E402

Session = sessionmaker()

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "5e7b5346c330"
down_revision = "2a6c63397399"
branch_labels = None
depends_on = None

users = sa.table(
    "users",
    sa.column("user_name", sa.String),
    sa.column("id", sa.String),
)
groups = sa.table(
    "groups",
    sa.column("group_name", sa.String),
)
users_groups = sa.table(
    "users_groups",
    sa.column("group_id", sa.Integer),
    sa.column("user_id", sa.Integer),
)
groups_resources_permissions = sa.table(
    "groups_resources_permissions",
    sa.column("group_id", sa.Integer),
    sa.column("resource_id", sa.Integer),
    sa.column("perm_name", sa.String),
)
users_resources_permissions = sa.table(
    "users_resources_permissions",
    sa.column("user_id", sa.Integer),
    sa.column("resource_id", sa.Integer),
    sa.column("perm_name", sa.String),
)


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())
    if isinstance(context.connection.engine.dialect, PGDialect):
        all_users = session.execute(sa.select([users]))
        all_groups = session.execute(sa.select([groups]))
        all_user_group_refs = session.execute(sa.select([users_groups]))
        all_grp_res_perms = session.execute(sa.select([groups_resources_permissions]))

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
                query = sa.select([users]).where(users.c.user_name == group_name)
                user = session.execute(query).fetchone()

                # transfer permissions from 'personal' group to user
                user_group_res_perm = [urp for urp in all_grp_res_perms if urp.group_id == group.id]
                for group_perm in user_group_res_perm:
                    session.execute(users_resources_permissions.insert().values(
                        user_id=user.id, resource_id=group_perm.resource_id, perm_name=group_perm.perm_name)
                    )
                    session.delete(group_perm)

                # delete obsolete personal group and corresponding user-group references
                for usr_grp in all_user_group_refs:
                    if usr_grp.group_id == group.id:
                        session.delete(usr_grp)
                session.delete(group)

        session.commit()


def downgrade():
    pass
