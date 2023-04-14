"""
Case Insensitive Email Constraint.

Revision ID: 5e5acc33adce
Revises: 0c6269f410cd
Create Date: 2022-09-01 21:16:40.175730
"""

from alembic import op
from sqlalchemy import text

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "5e5acc33adce"
down_revision = "0c6269f410cd"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "ix_users_email_unique_case_insensitive",
        "users",
        [text("lower(email)")],
        unique=True,
    )


def downgrade():
    op.drop_index("ix_users_email_unique_case_insensitive", "users")
