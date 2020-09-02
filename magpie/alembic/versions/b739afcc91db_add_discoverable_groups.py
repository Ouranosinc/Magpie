"""
Add discoverable groups.

Revision ID: b739afcc91db
Revises: 24da162a54f1
Create Date: 2020-07-23 15:54:22.850077
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "b739afcc91db"
down_revision = "24da162a54f1"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("groups", sa.Column("discoverable", sa.Boolean(), server_default=False, nullable=False))


def downgrade():
    op.drop_column("groups", "discoverable")
