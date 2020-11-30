"""
Group permission priority.

Revision ID: 9d977cce1ef2
Revises: cfe64807c143
Create Date: 2020-11-30 15:24:57.320156
"""

import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm.session import sessionmaker

# revision identifiers, used by Alembic.
revision = "9d977cce1ef2"
down_revision = "cfe64807c143"
branch_labels = None
depends_on = None

Session = sessionmaker()
groups = sa.table(
    "groups",
    sa.column("priority", sa.Integer()),
)


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())

    # two following lines avoids double "DELETE" erroneous call when deleting group due to incorrect checks
    # https://stackoverflow.com/questions/28824401
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    if isinstance(context.connection.engine.dialect, PGDialect):
        op.add_column("groups", sa.Column("priority", sa.Integer(), nullable=False, default=0, server_default="0"))
        stmt = groups.update().where(groups.c.priority is None).values({"priority": 0})
        session.execute(stmt)
        session.commit()


def downgrade():
    op.drop_column("groups", "priority")
