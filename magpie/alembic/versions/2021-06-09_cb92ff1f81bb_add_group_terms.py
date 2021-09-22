"""
add group terms

Revision ID: cb92ff1f81bb
Revises: 954a9d7fe740
Create Date: 2021-06-09 14:18:32.777082
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "cb92ff1f81bb"
down_revision = "954a9d7fe740"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("groups", sa.Column("terms", sa.UnicodeText(), nullable=True))


def downgrade():
    op.drop_column("groups", "terms")
