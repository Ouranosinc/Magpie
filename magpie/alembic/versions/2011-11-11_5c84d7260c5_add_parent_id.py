"""
Add id/parent id to resource structure.

Revision ID: 5c84d7260c5
Revises: 24ab8d11f014
Create Date: 2011-11-11 00:09:09.624704
"""
from __future__ import unicode_literals

import sqlalchemy as sa  # noqa: F401
from alembic import op  # noqa: F401

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "5c84d7260c5"
down_revision = "24ab8d11f014"


def upgrade():
    op.add_column(
        "resources", sa.Column("parent_id", sa.BigInteger(),
                               sa.ForeignKey("resources.resource_id",
                                             onupdate="CASCADE",
                                             ondelete="SET NULL")))


def downgrade():
    pass
