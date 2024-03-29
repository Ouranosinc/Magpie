"""
unified api service.

Revision ID: 73639c63c4fc
Revises: d01af1f2e445
Create Date: 2018-09-27 16:12:02.282830
"""
import sqlalchemy as sa
from alembic import op
from alembic.context import get_context  # noqa: F401
from sqlalchemy import func
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy.sql import table

Session = sessionmaker()

# Revision identifiers, used by Alembic.
# pylint: disable=C0103,invalid-name  # revision control variables not uppercase
revision = "73639c63c4fc"
down_revision = "d01af1f2e445"
branch_labels = None
depends_on = None


def upgrade():
    context = get_context()
    if isinstance(context.connection.engine.dialect, PGDialect):
        # add "sync_type" column if missing
        op.add_column("services", sa.Column("sync_type", sa.UnicodeText(), nullable=True))

        services = table("services",
                         sa.Column("url", sa.UnicodeText()),
                         sa.Column("type", sa.UnicodeText()),
                         sa.Column("sync_type", sa.UnicodeText()),
                         )

        # transfer "api" service types
        op.execute(services.
                   update().
                   where(services.c.type == op.inline_literal("project-api")).
                   values({"type": op.inline_literal("api"),
                           "url": services.c.url + "/api",
                           "sync_type": op.inline_literal("project-api")
                           })
                   )
        op.execute(services.
                   update().
                   where(services.c.type == op.inline_literal("geoserver-api")).
                   values({"type": op.inline_literal("api"),
                           "sync_type": op.inline_literal("geoserver-api")
                           })
                   )


def downgrade():
    service = table("services",
                    sa.Column("url", sa.UnicodeText()),
                    sa.Column("type", sa.UnicodeText()),
                    sa.Column("sync_type", sa.UnicodeText()),
                    )

    # transfer "api" service types
    op.execute(service.
               update().
               where(service.c.sync_type == op.inline_literal("project-api")).
               values({"type": op.inline_literal("project-api"),
                       "url": func.replace(service.c.url, "/api", ""),
                       })
               )
    op.execute(service.
               update().
               where(service.c.sync_type == op.inline_literal("geoserver-api")).
               values({"type": op.inline_literal("geoserver-api"),
                       })
               )

    op.drop_column("services", "sync_type")
