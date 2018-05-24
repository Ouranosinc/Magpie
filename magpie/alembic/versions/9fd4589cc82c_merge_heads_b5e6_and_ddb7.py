"""merge heads b5e6 and ddb7

Revision ID: 9fd4589cc82c
Revises: b5e6dd3449dd, ddb788864221
Create Date: 2018-05-23 17:17:01.347552

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9fd4589cc82c'
down_revision = (u'b5e6dd3449dd', 'ddb788864221')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
