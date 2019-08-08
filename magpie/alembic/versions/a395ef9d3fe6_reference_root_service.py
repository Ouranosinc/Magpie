"""reference root service

Revision ID: a395ef9d3fe6
Revises: ae1a3c8c7860
Create Date: 2018-06-04 11:38:31.296950

"""
import os
import sys
cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)    # version
root_dir = os.path.dirname(root_dir)    # alembic
root_dir = os.path.dirname(root_dir)    # magpie
root_dir = os.path.dirname(root_dir)    # root
sys.path.insert(0, root_dir)

# noinspection PyUnresolvedReferences
from alembic.context import get_context                                                 # noqa: F401
from alembic import op                                                                  # noqa: F401
from magpie.api.management.resource.resource_utils import get_resource_root_service     # noqa: F401
from magpie.definitions.sqlalchemy_definitions import (                                 # noqa: F401
    PGDialect, sessionmaker, sa, declarative_base, declared_attr
)

# revision identifiers, used by Alembic.
revision = 'a395ef9d3fe6'
down_revision = 'ae1a3c8c7860'
branch_labels = None
depends_on = None

Session = sessionmaker()


class BaseResource(declarative_base()):
    """
    Minimal Resource type definition without other dependencies in order to update entries.

    Using :class:`magpie.models.Resource` results in errors due to *future* fields in migration history.
    """
    @declared_attr
    def __tablename__(self):
        return "resources"

    @declared_attr
    def resource_id(self):
        return sa.Column(
            sa.Integer(), primary_key=True, nullable=False, autoincrement=True
        )
    @declared_attr
    def parent_id(self):
        return sa.Column(
            sa.Integer(),
            sa.ForeignKey("resources.resource_id", onupdate="CASCADE", ondelete="SET NULL"),
        )
    @declared_attr
    def root_service_id(self):
        return sa.Column(
            sa.Integer,
            sa.ForeignKey("services.resource_id", onupdate="CASCADE", ondelete="SET NULL"), index=True)


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())

    # two following lines avoids double 'DELETE' erroneous call when deleting group due to incorrect checks
    # https://stackoverflow.com/questions/28824401
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    if isinstance(context.connection.engine.dialect, PGDialect):
        op.add_column('resources', sa.Column('root_service_id', sa.Integer(), nullable=True))

        # add existing resource references to their root service, loop through reference tree chain
        all_resources = session.query(BaseResource)
        for resource in all_resources:
            # same resource is returned if it is directly the service
            # otherwise, the resource chain is resolved to the top service
            service_resource = get_resource_root_service(resource, session)
            if service_resource.resource_id != resource.resource_id:
                resource.root_service_id = service_resource.resource_id
        session.commit()


def downgrade():
    context = get_context()
    if isinstance(context.connection.engine.dialect, PGDialect):
        op.drop_column('resources', 'root_service_id')
