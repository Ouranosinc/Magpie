"""
reference root service.

Revision ID: a395ef9d3fe6
Revises: ae1a3c8c7860
Create Date: 2018-06-04 11:38:31.296950
"""
import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm.session import sessionmaker

# revision identifiers, used by Alembic.
revision = "a395ef9d3fe6"
down_revision = "ae1a3c8c7860"
branch_labels = None
depends_on = None

Session = sessionmaker()

resources = sa.table(
    "resources", 
    sa.column("root_service_id", sa.Integer), 
    sa.column("resource_id", sa.Integer), 
    sa.column("parent_id", sa.Integer)
)


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())

    # two following lines avoids double "DELETE" erroneous call when deleting group due to incorrect checks
    # https://stackoverflow.com/questions/28824401
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    if isinstance(context.connection.engine.dialect, PGDialect):
        op.add_column("resources", sa.Column("root_service_id", sa.Integer(), nullable=True))

        # add existing resource references to their root service, loop through reference tree chain
        query = session.execute(sa.select([resources.c.resource_id, resources.c.parent_id]))

        for resource_id, parent_id in query:
            root_resource_id = resource_id
            while parent_id is not None:
                parent_resource = session.execute(
                    sa.select([resources.c.resource_id, resources.c.parent_id])
                    .where(resources.c.resource_id == parent_id)
                ).fetchone()
                root_resource_id, parent_id = parent_resource

            session.execute(
                resources.update().where(resources.c.resource_id == resource_id).
                values(root_service_id=root_resource_id)
            )

        session.commit()


def downgrade():
    context = get_context()
    if isinstance(context.connection.engine.dialect, PGDialect):
        op.drop_column("resources", "root_service_id")
