"""
Pending Users and statuses

Create table for pending users, and update existing user statuses '0' to '2' for WebhookError

Revision ID: dea413e13a8a
Revises: 954a9d7fe740
Create Date: 2021-04-16 17:38:36.030704
"""
import datetime

import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy.orm.session import sessionmaker


# revision identifiers, used by Alembic.
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
                    sa.Column("user_name", sa.Unicode(128), primary_key=True, unique=True),
                    sa.Column("user_password", sa.Unicode(256)),
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
