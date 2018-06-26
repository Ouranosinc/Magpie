"""reference root service

Revision ID: a395ef9d3fe6
Revises: ae1a3c8c7860
Create Date: 2018-06-04 11:38:31.296950

"""
import os, sys
cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)    # version
root_dir = os.path.dirname(root_dir)    # alembic
root_dir = os.path.dirname(root_dir)    # magpie
root_dir = os.path.dirname(root_dir)    # root
sys.path.insert(0, root_dir)

from alembic import op
from alembic.context import get_context
from definitions.sqlalchemy_definitions import *
from magpie import models
from magpie.api.management.resource.resource_utils import get_resource_root_service

Session = sessionmaker()


# revision identifiers, used by Alembic.
revision = 'a395ef9d3fe6'
down_revision = 'ae1a3c8c7860'
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())

    # two following lines avoids double 'DELETE' erroneous call when deleting group due to incorrect checks
    # https://stackoverflow.com/questions/28824401/sqlalchemy-attempting-to-twice-delete-many-to-many-secondary-relationship
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    if isinstance(context.connection.engine.dialect, PGDialect):

        # check if column exists, add it otherwise
        inspector = reflection.Inspector.from_engine(context.connection.engine)
        has_root_service_column = False
        for column in inspector.get_columns(table_name='resources'):
            if 'root_service_id' in column['name']:
                has_root_service_column = True
                break

        if not has_root_service_column:
            op.add_column('resources', sa.Column('root_service_id', sa.Integer(), nullable=True))

        # add existing resource references to their root service, loop through reference tree chain
        all_resources = session.query(models.Resource)
        for resource in all_resources:
            service_resource = get_resource_root_service(resource, session)
            if service_resource.resource_id != resource.resource_id:
                resource.root_service_id = service_resource.resource_id
        session.commit()


def downgrade():
    pass
