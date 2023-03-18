"""
Groups pkey change.

Revision ID: 3cfc41c4a5f0
Revises: 53927300c277
Create Date: 2012-06-27 02:15:58.776223
"""
from __future__ import unicode_literals

import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.mysql.base import MySQLDialect
from sqlalchemy.engine.reflection import Inspector

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "3cfc41c4a5f0"
down_revision = "53927300c277"


def upgrade():
    c = get_context()
    if isinstance(c.connection.engine.dialect, MySQLDialect):
        insp = Inspector.from_engine(c.connection.engine)
        for table in ["groups_permissions", "groups_resources_permissions", "users_groups", "resources"]:
            for constraint in insp.get_foreign_keys(table):
                if constraint["referred_columns"] == ["group_name"]:
                    op.drop_constraint(constraint["name"], table, "foreignkey")

    op.drop_column("groups", "id")
    op.alter_column("groups", "group_name",
                    type_=sa.Unicode(128),
                    existing_type=sa.Unicode(50),
                    )
    op.create_primary_key("groups_pkey", "groups", ["group_name"])

    if isinstance(c.connection.engine.dialect, MySQLDialect):
        op.create_foreign_key(None, "groups_permissions", "groups",
                              remote_cols=["group_name"],
                              local_cols=["group_name"], onupdate="CASCADE",
                              ondelete="CASCADE")
        op.create_foreign_key(None, "groups_resources_permissions", "groups",
                              remote_cols=["group_name"],
                              local_cols=["group_name"], onupdate="CASCADE",
                              ondelete="CASCADE")
        op.create_foreign_key(None, "users_groups", "groups",
                              remote_cols=["group_name"],
                              local_cols=["group_name"], onupdate="CASCADE",
                              ondelete="CASCADE")
        op.create_foreign_key(None, "resources", "groups",
                              remote_cols=["group_name"],
                              local_cols=["owner_group_name"],
                              onupdate="CASCADE",
                              ondelete="SET NULL")


def downgrade():
    pass
