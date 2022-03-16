"""
Apply THREDDS BROWSE permission for resources with READ.

Due to the addition of metadata BROWSE permission, any pre-existing resource with READ permissions for user/group
that previously handled both metadata and data access would become denied access for metadata-related access.
Automatically assign the corresponding permission to make change transparent for pre-existing resources.

Revision ID: 9b8e5d37f684
Revises: 5f2648b8ff49
Create Date: 2020-10-28 12:49:22.735259
"""

import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm.session import sessionmaker
from ziggurat_foundations.models.services.group_resource_permission import GroupResourcePermissionService
from ziggurat_foundations.models.services.user_resource_permission import UserResourcePermissionService

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "9b8e5d37f684"
down_revision = "5f2648b8ff49"
branch_labels = None
depends_on = None

Session = sessionmaker()

services = sa.table(
    "services",
    sa.column("resource_id", sa.Integer),
    sa.column("type", sa.UnicodeText)
)
resources = sa.table(
    "resources",
    sa.column("resource_id", sa.Integer),
    sa.column("root_service_id", sa.Integer)
)
grp_res_perms = sa.table(
    "groups_resources_permissions",
    sa.column("group_id", sa.Integer),
    sa.column("resource_id", sa.Integer),
    sa.column("perm_name", sa.UnicodeText)
)
usr_res_perms = sa.table(
    "users_resources_permissions",
    sa.column("user_id", sa.Integer),
    sa.column("resource_id", sa.Integer),
    sa.column("perm_name", sa.UnicodeText)
)


def duplicate_browse(resource_id, session):
    grp_query = sa.select([grp_res_perms]).where(grp_res_perms.c.resource_id == resource_id)
    grp_perms = session.execute(grp_query)
    usr_query = sa.select([usr_res_perms]).where(usr_res_perms.c.resource_id == resource_id)
    usr_perms = session.execute(usr_query)

    for perm in grp_perms:
        if not perm.perm_name.startswith("read"):  # must consider any variant with [access]-[scope]
            continue
        perm_name = perm.perm_name.replace("read", "browse")
        query = sa.insert(grp_res_perms, (perm.group_id, resource_id, perm_name))
        session.execute(query)

    for perm in usr_perms:
        if not perm.perm_name.startswith("read"):  # must consider any variant with [access]-[scope]
            continue
        perm_name = perm.perm_name.replace("read", "browse")
        query = sa.insert(usr_res_perms, (perm.user_id, resource_id, perm_name))
        session.execute(query)


def upgrade():
    """
    Duplicate THREDDS Service and sub-resources READ permissions with BROWSE.
    """
    session = Session(bind=op.get_bind())

    query = sa.select([services]).where(services.c.type == "thredds")
    thredds_services = session.execute(query)

    for svc in thredds_services:
        svc_id = svc.resource_id
        duplicate_browse(svc_id, session)

        query = sa.select([resources]).where(resources.c.root_service_id == svc_id)
        child_resources = session.execute(query)
        for res in child_resources:
            duplicate_browse(res.resource_id, session)

    session.commit()


def downgrade():
    """
    Any existing 'BROWSE' permission must be dropped.
    """
    context = get_context()
    session = Session(bind=op.get_bind())
    if not isinstance(context.connection.engine.dialect, PGDialect):
        return

    # two following lines avoids double "DELETE" erroneous call (ignore duplicate)
    # https://stackoverflow.com/questions/28824401
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    grp_perms = GroupResourcePermissionService.base_query(db_session=session)
    usr_perms = UserResourcePermissionService.base_query(db_session=session)
    for perm in grp_perms:
        if perm.perm_name == "browse":
            session.delete(perm)
    for perm in usr_perms:
        if perm.perm_name == "browse":
            session.delete(perm)
    session.commit()
