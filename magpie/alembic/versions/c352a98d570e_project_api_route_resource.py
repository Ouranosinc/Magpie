"""project-api route resource

Revision ID: c352a98d570e
Revises: a395ef9d3fe6
Create Date: 2018-06-20 13:31:55.666240

"""
import os, sys
cur_file = os.path.abspath(__file__)
root_dir = os.path.dirname(cur_file)    # version
root_dir = os.path.dirname(root_dir)    # alembic
root_dir = os.path.dirname(root_dir)    # magpie
root_dir = os.path.dirname(root_dir)    # root
sys.path.insert(0, root_dir)

from magpie.definitions.alembic_definitions import *
from magpie.definitions.sqlalchemy_definitions import *
from magpie import models
from magpie.models import *


# revision identifiers, used by Alembic.
revision = 'c352a98d570e'
down_revision = 'a395ef9d3fe6'
branch_labels = None
depends_on = None

Session = sessionmaker()

def change_project_api_resource_type(new_type_name):
    context = get_context()
    if isinstance(context.connection.engine.dialect, PGDialect):
        # obtain service 'project-api'
        session = Session(bind=op.get_bind())
        project_api_svc = models.Service.by_service_name('project-api', db_session=session)

        # nothing to edit if it doesn't exist, otherwise change resource types to 'route'
        if project_api_svc:
            project_api_id = project_api_svc.resource_id
            project_api_res = session.query(models.Resource).filter(models.Resource.root_service_id == project_api_id)

            for res in project_api_res:
                res.resource_type = 'route'

            session.commit()

def upgrade():
    change_project_api_resource_type('route')


def downgrade():
    change_project_api_resource_type('directory')
