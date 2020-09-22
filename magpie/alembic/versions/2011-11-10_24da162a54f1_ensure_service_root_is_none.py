"""
ensure_service_root_is_none.

Revision ID: 24da162a54f1
Revises: 03b54feffe45
Create Date: 2019-11-06 16:26:56.898075
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '24da162a54f1'
down_revision = '03b54feffe45'
branch_labels = None
depends_on = None

resources = sa.table(
    "resources", 
    sa.column("root_service_id", sa.Integer), 
    sa.column("resource_id", sa.Integer), 
    sa.column("parent_id", sa.Integer)
)


def upgrade():
    # pylint: disable=no-member
    op.execute(resources.
               update().
               where(resources.c.resource_id == resources.c.root_service_id).
               values(root_service_id=None)
               )


def downgrade():
    # pylint: disable=no-member
    op.execute(resources.
               update().
               where(resources.c.root_service_id.is_(None)).
               values(root_service_id=resources.c.resource_id)
               )
