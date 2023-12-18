"""
Add Network_Tokens Table

Revision ID: 2cfe144538e8
Revises: 5e5acc33adce
Create Date: 2023-08-25 13:36:16.930374
"""
import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy_utils import URLType

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "2cfe144538e8"
down_revision = "5e5acc33adce"
branch_labels = None
depends_on = None

Session = sessionmaker()


def upgrade():
    op.create_table("network_tokens",
                    sa.Column("id", sa.Integer, primary_key=True, nullable=False, autoincrement=True),
                    sa.Column("token", sa.String, nullable=False, unique=True),
                    sa.Column("created", sa.DateTime, default=datetime.datetime.utcnow)
                    )
    op.create_table("network_nodes",
                    sa.Column("id", sa.Integer, primary_key=True, nullable=False, autoincrement=True),
                    sa.Column("name", sa.Unicode(128), nullable=False, unique=True),
                    sa.Column("jwks_url", URLType(), nullable=False),
                    sa.Column("token_url", URLType(), nullable=False),
                    sa.Column("authorization_url", URLType(), nullable=False),
                    sa.Column("redirect_uris", sa.JSON, nullable=False, server_default='[]')
                    )
    op.create_table("network_remote_users",
                    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
                    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", onupdate="CASCADE", ondelete="CASCADE"),
                              nullable=False),
                    sa.Column("network_node_id", sa.Integer,
                              sa.ForeignKey("network_nodes.id", onupdate="CASCADE", ondelete="CASCADE"),
                              nullable=False),
                    sa.Column("name", sa.Unicode(128)),
                    sa.Column("network_token_id", sa.Integer,
                              sa.ForeignKey("network_tokens.id", onupdate="CASCADE", ondelete="CASCADE"), unique=True)
                    )
    op.create_unique_constraint("uq_network_remote_users_user_id_network_node_id", "network_remote_users",
                                ["user_id", "network_node_id"])
    op.create_unique_constraint("uq_network_remote_users_name_network_node_id", "network_remote_users",
                                ["name", "network_node_id"])


def downgrade():
    op.drop_constraint("uq_network_remote_users_user_id_network_node_id", "network_remote_users")
    op.drop_constraint("uq_network_remote_users_name_network_node_id", "network_remote_users")
    op.drop_table("network_tokens")
    op.drop_table("network_nodes")
    op.drop_table("network_remote_users")
