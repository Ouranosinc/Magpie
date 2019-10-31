"""
add resource_display_name column

Revision ID: 73b872478d87
Revises: d01af1f2e445
Create Date: 2018-09-24 11:29:38.108819
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '73b872478d87'
down_revision = '73639c63c4fc'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('resources', sa.Column('resource_display_name', sa.Unicode(100), nullable=True))
    op.add_column('remote_resources', sa.Column('resource_display_name', sa.Unicode(100), nullable=True))


def downgrade():
    op.drop_column('resources', 'resource_display_name')
    op.drop_column('remote_resources', 'resource_display_name')
