"""
Add service custom configuration field.

Revision ID: cfe64807c143
Revises: 9b8e5d37f684
Create Date: 2020-11-20 15:05:10.353336
"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "cfe64807c143"
down_revision = "9b8e5d37f684"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("services", sa.Column("configuration", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("services", "configuration")
