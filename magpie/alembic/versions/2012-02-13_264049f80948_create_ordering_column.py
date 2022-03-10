"""
Create ordering column.

Revision ID: 264049f80948
Revises: 46a9c4fb9560
Create Date: 2012-02-13 20:32:34.542829
"""
from __future__ import unicode_literals

import sqlalchemy as sa  # noqa: F401
from alembic import op  # noqa: F401

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "264049f80948"
down_revision = "46a9c4fb9560"


def upgrade():
    op.add_column("resources", sa.Column("ordering", sa.Integer,
                                         server_default="0", nullable=False))


def downgrade():
    pass
