"""unified api service

Revision ID: 73639c63c4fc
Revises: d01af1f2e445
Create Date: 2018-09-27 16:12:02.282830

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
from magpie.definitions.sqlalchemy_definitions import *
from magpie import models
from magpie.api.management.resource.resource_utils import get_resource_root_service

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
        for service in models.Service.all(db_session=session):
            if service.type == 'project-api':
                service.type = 'api'
                service.url = service.url + '/api'
            elif service.type == 'geoserver-api':
                service.type = 'api'
                service.url = service.url.rstrip('/')
    session.commit()


def downgrade():
    context = get_context()
    session = Session(bind=op.get_bind())
    if isinstance(context.connection.engine.dialect, PGDialect):
        for service in models.Service.all(db_session=session):
            if service.type == 'api':
                if 'geoserver/rest' in service.url:
                    service.type = 'geoserver-api'
                else:
                    service.type = 'project-api'
                    service.url = service.url.rstrip('/api')
    session.commit()
