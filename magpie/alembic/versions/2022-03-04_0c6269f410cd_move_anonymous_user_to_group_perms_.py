"""
Move anonymous user to anonymous group permissions.

Revision ID: 0c6269f410cd
Revises: cb92ff1f81bb
Create Date: 2022-03-04 23:13:39.987696
"""

import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.orm.session import sessionmaker

from magpie.constants import get_constant  # isort:skip # noqa: E402

# revision identifiers, used by Alembic.
revision = "0c6269f410cd"
down_revision = "cb92ff1f81bb"
branch_labels = None
depends_on = None

Session = sessionmaker()
groups = sa.table(
    "groups",
    sa.column("id", sa.Integer),
    sa.column("group_name", sa.String),
)
users = sa.table(
    "users",
    sa.column("id", sa.Integer),
    sa.column("user_name", sa.String),
)
grp_res_perms = sa.table(
    "groups_resources_permissions",
    sa.column("group_id", sa.Integer),
    sa.column("resource_id", sa.String),
    sa.column("perm_name", sa.Integer)
)
usr_res_perms = sa.table(
    "users_resources_permissions",
    sa.column("user_id", sa.Integer),
    sa.column("resource_id", sa.String),
    sa.column("perm_name", sa.Integer)
)


def upgrade():
    session = Session(bind=op.get_bind())
    anon_usr_name = get_constant("MAGPIE_ANONYMOUS_USER")
    anon_grp_name = get_constant("MAGPIE_ANONYMOUS_GROUP")
    anon_usr = session.execute(sa.select([users]).where(users.c.user_name == anon_usr_name)).fetchone()
    anon_grp = session.execute(sa.select([groups]).where(groups.c.group_name == anon_grp_name)).fetchone()
    anon_usr_res_perms = session.execute(sa.select([usr_res_perms]).where(usr_res_perms.c.user_id == anon_usr.id))
    anon_grp_res_perms = session.execute(sa.select([grp_res_perms]).where(grp_res_perms.c.group_id == anon_grp.id))
    for urp in anon_usr_res_perms:
        # prioritize existing permission on group over user, regardless of permission name
        if not any(grp.resource_id == urp.resource_id for grp in anon_grp_res_perms):
            sa.insert(grp_res_perms, (anon_grp.id, urp.resource_id, urp.perm_name))
        session.delete(urp)
    session.commit()


def downgrade():
    pass  # nothing to do, having anonymous group permissions is still valid
