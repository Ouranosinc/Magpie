"""
ensure anonymous group applied to users.

Revision ID: 03b54feffe45
Revises: 73b872478d87
Create Date: 2019-08-23 18:08:07.507556
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

users = sa.table(
    "users",
    sa.column("id", sa.Integer),
    sa.column("user_name", sa.String),
)
groups = sa.table(
    "groups",
    sa.column("id", sa.Integer),
    sa.column("group_name", sa.String),
    sa.column("member_count", sa.Integer)
)
users_groups = sa.table(
    "users_groups",
    sa.column("user_id", sa.Integer),
    sa.column("group_id", sa.Integer),
)


# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "03b54feffe45"
down_revision = "73b872478d87"
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())

    # two following lines avoids double 'DELETE' erroneous call when deleting group due to incorrect checks
    # https://stackoverflow.com/questions/28824401
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    if isinstance(context.connection.engine.dialect, PGDialect):
        all_user_ids = set(session.execute(sa.select([users.c.id])))

        # make sure group exists, then get it
        anonym_name = get_constant("MAGPIE_ANONYMOUS_GROUP")
        query = sa.select([groups]).where(groups.c.group_name == anonym_name)
        anonym_group = session.execute(query).fetchone()
        if not anonym_group:
            session.execute(groups.insert().values(group_name=anonym_name, member_count=len(all_user_ids)))
            anonym_group = session.execute(query).fetchone()

        query = sa.select([users_groups.c.user_id]).where(users_groups.c.group_id == anonym_group.id)
        users_with_anonym = session.execute(query)
        users_with_anonym = set(users_with_anonym or [])  # handle if None
        missing_grp_users = all_user_ids - users_with_anonym
        missing_grp_users = [{"user_id": usr_id, "group_id": anonym_group.id} for usr_id in missing_grp_users]
        if missing_grp_users:
            session.execute(users_groups.insert(), missing_grp_users)
        session.commit()


def downgrade():
    pass
