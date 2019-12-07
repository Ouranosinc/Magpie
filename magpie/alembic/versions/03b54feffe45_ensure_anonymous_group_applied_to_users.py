"""
ensure anonymous group applied to users.

Revision ID: 03b54feffe45
Revises: 73b872478d87
Create Date: 2019-08-23 18:08:07.507556
"""
from alembic.context import get_context  # noqa: F401
from alembic import op
from sqlalchemy.orm import sessionmaker
from magpie import models, constants
from magpie.definitions.ziggurat_definitions import GroupService, BaseService
from magpie.definitions.sqlalchemy_definitions import PGDialect
from magpie.helpers.register_default_users import init_anonymous
Session = sessionmaker()


# revision identifiers, used by Alembic.
revision = '03b54feffe45'
down_revision = '73b872478d87'
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    session = Session(bind=op.get_bind())

    # two following lines avoids double 'DELETE' erroneous call when deleting group due to incorrect checks
    # https://stackoverflow.com/questions/28824401
    context.connection.engine.dialect.supports_sane_rowcount = False
    context.connection.engine.dialect.supports_sane_multi_rowcount = False

    if isinstance(context.connection.engine.dialect, PGDialect):
        # make sure group exists, then get it
        init_anonymous(db_session=session)
        anonym_group = GroupService.by_group_name(constants.get_constant("MAGPIE_ANONYMOUS_GROUP"), db_session=session)

        all_users = BaseService.all(models.User, db_session=session)
        all_user_group_refs = BaseService.all(models.UserGroup, db_session=session)
        all_user_group_tups = [(ugr.user_id, ugr.group_id) for ugr in all_user_group_refs]
        for user in all_users:
            if (user.id, anonym_group.id) not in all_user_group_tups:
                # noinspection PyArgumentList
                user_group = models.UserGroup(user_id=user.id, group_id=anonym_group.id)
                session.add(user_group)
        session.commit()


def downgrade():
    pass
