"""
${message.title()}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm.session import sessionmaker

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
%if up_revision:
revision = "${up_revision}"
%else:
revision = None
%endif
%if down_revision:
down_revision = "${down_revision}"
%else:
down_revision = None
%endif
%if branch_labels:
branch_labels = "${branch_labels}"
%else:
branch_labels = None
%endif
%if depends_one:
depends_on = "${depends_on}"
%else:
depends_on = None
%endif

Session = sessionmaker()


def upgrade():
    ${upgrades if upgrades else "pass"}


def downgrade():
    ${downgrades if downgrades else "pass"}
