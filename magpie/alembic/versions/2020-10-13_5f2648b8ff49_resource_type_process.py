"""
Resources of type Process introduced.

Revision ID: 5f2648b8ff49
Revises: a2a039e2cff5
Create Date: 2020-10-13 16:20:07.323467
"""

from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm.session import sessionmaker
from ziggurat_foundations.models.services.resource import ResourceService

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "5f2648b8ff49"
down_revision = "a2a039e2cff5"
branch_labels = None
depends_on = None

Session = sessionmaker()


def upgrade():
    # nothing to be done when upgrading
    pass


def downgrade():
    # any existing 'Process' resource must be dropped
    context = get_context()
    session = Session(bind=op.get_bind())
    if not isinstance(context.connection.engine.dialect, PGDialect):
        return

    # two following lines avoids double "DELETE" erroneous call (ignore duplicate)
    # https://stackoverflow.com/questions/28824401
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    resources = ResourceService.base_query(db_session=session)
    for res in resources:
        if res.resource_type == "process":
            session.delete(res)
    session.commit()
