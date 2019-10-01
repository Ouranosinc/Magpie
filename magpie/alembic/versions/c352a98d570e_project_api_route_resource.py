"""
project-api route resource.

Revision ID: c352a98d570e
Revises: a395ef9d3fe6
Create Date: 2018-06-20 13:31:55.666240
"""
import os
import sys

import sqlalchemy as sa

cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)    # version
root_dir = os.path.dirname(root_dir)    # alembic
root_dir = os.path.dirname(root_dir)    # magpie
root_dir = os.path.dirname(root_dir)    # root
sys.path.insert(0, root_dir)

# noinspection PyUnresolvedReferences
from magpie.definitions.alembic_definitions import get_context, op              # noqa: F401
from magpie.definitions.sqlalchemy_definitions import PGDialect, sessionmaker   # noqa: F401

# revision identifiers, used by Alembic.
revision = 'c352a98d570e'
down_revision = 'a395ef9d3fe6'
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
        query = sa.select([services.c.resource_id]).where(services.c.type == 'project-api')
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
    change_project_api_resource_type('route')


def downgrade():
    change_project_api_resource_type('directory')
