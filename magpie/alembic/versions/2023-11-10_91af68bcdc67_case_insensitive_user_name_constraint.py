"""
Case Insensitive User_Name Constraint

Revision ID: 91af68bcdc67
Revises: 5e5acc33adce
Create Date: 2023-11-10 15:58:23.068465
"""
import sqlalchemy
import sqlalchemy as sa
from alembic import op
from sqlalchemy import func
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
    # If users with conflicting user_names already exist, the following will fail. The conflicting user_names
    # must be updated manually and then this migration script can be re-run.
    try:
        op.create_index(
            "ix_users_user_name_unique_case_insensitive",
            "users",
            [sa.text("lower(user_name)")],
            unique=True,
        )
    except sqlalchemy.exc.IntegrityError as e:
        raise Exception("{}\nPlease manually update conflicting user_names and try again".format(e)) from e
    session = Session(bind=op.get_bind())
    session.execute(users.update().values({users.c.user_name: func.lower(users.c.user_name)}))
    session.commit()


def downgrade():
    op.drop_index("ix_users_user_name_unique_case_insensitive", "users")
    # Previous case information is lost and cannot be restored
