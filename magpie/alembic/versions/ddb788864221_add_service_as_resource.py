"""
add service as resource.

Revision ID: ddb788864221
Revises: 0974132183ad
Create Date: 2017-07-21 18:44:53.429481
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'ddb788864221'
down_revision = '0974132183ad'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('services',
                    sa.Column('resource_id',
                              sa.Integer(),
                              sa.ForeignKey('resources.resource_id',
                                            onupdate='CASCADE',
                                            ondelete='CASCADE', ),
                              primary_key=True),
                    sa.Column('type', sa.UnicodeText(), unique=False),
                    sa.Column('url', sa.UnicodeText(), unique=False))


def downgrade():
    pass
