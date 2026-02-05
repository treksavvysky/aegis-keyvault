"""add secret_type column

Revision ID: 0003
Revises: 0002
Create Date: 2026-02-05 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "secrets",
        sa.Column("secret_type", sa.String(length=50), nullable=True, server_default="password"),
    )


def downgrade() -> None:
    op.drop_column("secrets", "secret_type")
