"""
alter user.

Revision ID: 0974132183ad
Revises:
Create Date: 2017-07-21 18:40:24.918345
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0974132183ad'
down_revision = None
branch_labels = None
depends_on = '2bb1ba973f0b'


def upgrade():
    op.add_column('users', sa.Column('openid', sa.Unicode(128), unique=True))
    op.add_column('users', sa.Column('credential', sa.Unicode(128), unique=True))
    op.add_column('users', sa.Column('cert_expires', sa.TIMESTAMP(timezone=False),
                                     default=sa.sql.func.now(), server_default=sa.func.now()))


def downgrade():
    pass
