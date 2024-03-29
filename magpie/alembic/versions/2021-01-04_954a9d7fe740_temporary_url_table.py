"""
Temporary URL table.

Revision ID: 954a9d7fe740
Revises: cfe64807c143
Create Date: 2021-01-04 12:56:22.298527
"""

import datetime
import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "954a9d7fe740"
down_revision = "cfe64807c143"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("tmp_tokens",
                    sa.Column("token", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True),
                    sa.Column("operation", sa.Unicode(32), nullable=False),
                    sa.Column("user_id", sa.Integer,
                              sa.ForeignKey("users.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=True),
                    sa.Column("group_id", sa.Integer(),
                              sa.ForeignKey("groups.id", onupdate="CASCADE", ondelete="CASCADE"), nullable=True),
                    sa.Column("created", sa.DateTime, default=datetime.datetime.utcnow)
                    )


def downgrade():
    op.drop_table("tmp_tokens")
