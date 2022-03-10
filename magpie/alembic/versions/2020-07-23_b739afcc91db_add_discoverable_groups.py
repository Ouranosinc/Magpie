"""
Add discoverable groups.

Revision ID: b739afcc91db
Revises: 24da162a54f1
Create Date: 2020-07-23 15:54:22.850077
"""
import sqlalchemy as sa
from alembic import op

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "b739afcc91db"
down_revision = "24da162a54f1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("groups", sa.Column("discoverable", sa.Boolean, nullable=False,
                                      server_default=sa.schema.DefaultClause("0")))


def downgrade():
    op.drop_column("groups", "discoverable")
