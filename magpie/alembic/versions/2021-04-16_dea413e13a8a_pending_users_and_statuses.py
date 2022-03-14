"""
Pending Users and statuses.

Create table for pending users, and update existing user statuses '0' to '2' for WebhookError

Revision ID: dea413e13a8a
Revises: 954a9d7fe740
Create Date: 2021-04-16 17:38:36.030704
"""
import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm.session import sessionmaker

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "dea413e13a8a"
down_revision = "954a9d7fe740"
branch_labels = None
depends_on = None

Session = sessionmaker()
User = sa.table(
    "users",
    sa.column("status", sa.SmallInteger)
)


def upgrade():
    op.create_table("users_pending",
                    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
                    sa.Column("user_name", sa.Unicode(128), nullable=False, unique=True),
                    sa.Column("user_password", sa.Unicode(256), nullable=False),
                    sa.Column("email", sa.Unicode(100), nullable=False, unique=True),
                    sa.Column("registered_date", sa.TIMESTAMP(timezone=False),
                              default=datetime.datetime.utcnow, server_default=sa.func.now())
                    )

    session = Session(bind=op.get_bind())
    query = sa.update(User).where(User.c.status == 0).values(status=2)  # use literals to avoid enum value changes
    session.execute(query)
    session.commit()


def downgrade():
    op.drop_table("users_pending")

    # revert the webhook error status
    session = Session(bind=op.get_bind())
    query = sa.update(User).where(User.c.status == 2).values(status=0)  # use literals to avoid enum value changes
    session.execute(query)
    session.commit()
