"""
Unique user emails.

Revision ID: 00c617174e54
Revises: dea413e13a8a
Create Date: 2021-04-19 12:45:55.439916
"""

from alembic import op

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "00c617174e54"
down_revision = "dea413e13a8a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint("uq_users_email", "users", ["email"])


def downgrade():
    op.drop_constraint("uq_users_email", "users", type="unique")
