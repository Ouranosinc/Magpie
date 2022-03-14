"""
Create a column to allow TokenOperation reference to UserPending entry.

Revision ID: 35e98bdc8aed
Revises: 00c617174e54
Create Date: 2021-04-27 18:58:34.606126
"""

import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "35e98bdc8aed"
down_revision = "00c617174e54"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "tmp_tokens",
        sa.Column("user_pending_id", sa.Integer,
                  sa.ForeignKey("users_pending.id", onupdate="CASCADE", ondelete="CASCADE"),
                  nullable=True)
    )


def downgrade():
    op.drop_column("tmp_tokens", "user_pending_id")
