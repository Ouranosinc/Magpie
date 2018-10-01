"""unified api service

Revision ID: 73639c63c4fc
Revises: d01af1f2e445
Create Date: 2018-09-27 16:12:02.282830

"""
import os, sys

cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)  # version
root_dir = os.path.dirname(root_dir)  # alembic
root_dir = os.path.dirname(root_dir)  # magpie
root_dir = os.path.dirname(root_dir)  # root
sys.path.insert(0, root_dir)

from alembic import op
from alembic.context import get_context
from magpie.definitions.sqlalchemy_definitions import *
from magpie.models import Service
from magpie.alembic.utils import has_column

Session = sessionmaker()

# revision identifiers, used by Alembic.
revision = '73639c63c4fc'
down_revision = 'd01af1f2e445'
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())
    if isinstance(context.connection.engine.dialect, PGDialect):
        # add 'sync_type' column if missing
        if not has_column(context, 'services', 'sync_type'):
            op.add_column('services', sa.Column('sync_type', sa.UnicodeText(), nullable=True))

        # transfer 'api' service types
        session.query(Service). \
            filter(Service.type == 'project-api'). \
            update({Service.type: 'api',
                    Service.url: Service.url + '/api',
                    Service.sync_type: 'project-api'}, synchronize_session=False)
        session.query(Service). \
            filter(Service.type == 'geoserver-api'). \
            update({Service.type: 'api',
                    Service.sync_type: 'geoserver-api'}, synchronize_session=False)
        session.commit()


def downgrade():
    context = get_context()
    session = Session(bind=op.get_bind())
    if isinstance(context.connection.engine.dialect, PGDialect):
        # transfer 'api' service types
        services_project_api = session.query(Service).filter(Service.sync_type == 'project-api')
        for svc in services_project_api:
            svc_url = svc.url.rstrip('/api')
            session.query(Service). \
                filter(Service.resource_id == svc.resource_id). \
                update({Service.type: 'project-api', Service.url: svc_url}, synchronize_session=False)
        session.flush()
        session.query(Service). \
            filter(Service.sync_type == 'geoserver-api'). \
            update({Service.type: 'geoserver-api'}, synchronize_session=False)
        session.flush()
        # drop 'sync_type' column
        if has_column(context, 'services', 'sync_type'):
            op.drop_column('services', 'sync_type')
        session.commit()
