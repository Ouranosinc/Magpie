"""
Case Insensitive User_Name Constraint

Revision ID: 91af68bcdc67
Revises: 5e5acc33adce
Create Date: 2023-11-10 15:58:23.068465
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm.session import sessionmaker

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "91af68bcdc67"
down_revision = "5e5acc33adce"
branch_labels = None
depends_on = None

Session = sessionmaker()

users = sa.table(
    "users",
    sa.column("id", sa.Integer),
    sa.column("user_name", sa.String),
)


def upgrade():
    op.create_index(
        "ix_users_user_name_unique_case_insensitive",
        "users",
        [sa.text("lower(user_name)")],
        unique=True,
    )
    session = Session(bind=op.get_bind())
    for user in session.execute(sa.select(users)):
        session.execute(users.update().where(users.c.id == user.id).values(user_name=user.user_name.lower()))
    session.commit()


def downgrade():
    op.drop_index("ix_users_user_name_unique_case_insensitive", "users")
    # Previous case information is lost and cannot be restored
