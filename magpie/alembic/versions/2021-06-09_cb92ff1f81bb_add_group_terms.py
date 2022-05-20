"""
Add group terms.

Revision ID: cb92ff1f81bb
Revises: 35e98bdc8aed
Create Date: 2021-06-09 14:18:32.777082
"""

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "cb92ff1f81bb"
down_revision = "35e98bdc8aed"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("groups", sa.Column("terms", sa.UnicodeText(), nullable=True))


def downgrade():
    op.drop_column("groups", "terms")
