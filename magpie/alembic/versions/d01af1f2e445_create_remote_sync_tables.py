"""
create remote sync tables.

Revision ID: d01af1f2e445
Revises: c352a98d570e
Create Date: 2018-09-11 10:56:23.779143
"""
from sqlalchemy.orm.session import sessionmaker
import sqlalchemy as sa
from alembic import op

Session = sessionmaker()


# revision identifiers, used by Alembic.
revision = "d01af1f2e445"
down_revision = "c352a98d570e"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("remote_resources",
                    sa.Column("resource_id", sa.Integer(), primary_key=True,
                              nullable=False, autoincrement=True),
                    sa.Column("service_id",
                              sa.Integer(),
                              sa.ForeignKey("services.resource_id", onupdate="CASCADE", ondelete="CASCADE"),
                              index=True,
                              nullable=False),
                    sa.Column("parent_id",
                              sa.Integer(),
                              sa.ForeignKey("remote_resources.resource_id", onupdate="CASCADE", ondelete="SET NULL"),
                              nullable=True),
                    sa.Column("ordering", sa.Integer(), default=0, nullable=False),
                    sa.Column("resource_name", sa.Unicode(100), nullable=False),
                    sa.Column("resource_type", sa.Unicode(30), nullable=False),
                    )
    op.create_table("remote_resources_sync_info",
                    sa.Column("id", sa.Integer(), primary_key=True, nullable=False, autoincrement=True),
                    sa.Column("service_id",
                              sa.Integer(),
                              sa.ForeignKey("services.resource_id", onupdate="CASCADE", ondelete="CASCADE"),
                              index=True,
                              nullable=False),
                    sa.Column("remote_resource_id",
                              sa.Integer(),
                              sa.ForeignKey("remote_resources.resource_id", onupdate="CASCADE", ondelete="CASCADE")),
                    sa.Column("last_sync", sa.DateTime(), nullable=True),
                    )


def downgrade():
    op.drop_table("remote_resources_sync_info")
    op.drop_table("remote_resources")
