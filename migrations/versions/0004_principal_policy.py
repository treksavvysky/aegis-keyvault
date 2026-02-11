"""add principal policy ceiling and api key resource binding

Revision ID: 0004
Revises: 0003
Create Date: 2026-02-06 00:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "principals",
        sa.Column("max_scopes_json", sa.JSON(), nullable=True),
    )
    op.add_column(
        "principals",
        sa.Column("max_resources_json", sa.JSON(), nullable=True),
    )
    op.add_column(
        "api_keys",
        sa.Column("allowed_resources_json", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("api_keys", "allowed_resources_json")
    op.drop_column("principals", "max_resources_json")
    op.drop_column("principals", "max_scopes_json")
