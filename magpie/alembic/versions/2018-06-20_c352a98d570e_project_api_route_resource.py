"""
Add project-api route resource.

Revision ID: c352a98d570e
Revises: a395ef9d3fe6
Create Date: 2018-06-20 13:31:55.666240
"""
import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm.session import sessionmaker

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "c352a98d570e"
down_revision = "a395ef9d3fe6"
branch_labels = None
depends_on = None

Session = sessionmaker()

services = sa.table(
    "services",
    sa.column("resource_id", sa.Integer),
    sa.column("type", sa.String),
)

resources = sa.table(
    "resources",
    sa.column("resource_id", sa.Integer),
    sa.column("resource_type", sa.String),
    sa.column("root_service_id", sa.Integer),
)


def change_project_api_resource_type(new_type_name):
    context = get_context()
    if isinstance(context.connection.engine.dialect, PGDialect):
        # obtain service 'project-api'
        session = Session(bind=op.get_bind())
        query = sa.select([services.c.resource_id]).where(services.c.type == "project-api")
        project_api_svc = session.execute(query).fetchone()

        # nothing to edit if it doesn't exist, otherwise change resource types name
        if project_api_svc is not None:
            stmt = (
                resources.update()
                .where(resources.c.root_service_id == project_api_svc.resource_id)
                .values({"resource_type": new_type_name})
            )
            session.execute(stmt)
            session.commit()


def upgrade():
    change_project_api_resource_type("route")


def downgrade():
    change_project_api_resource_type("directory")
