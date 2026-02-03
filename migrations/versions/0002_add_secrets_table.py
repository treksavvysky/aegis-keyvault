"""add secrets table

Revision ID: 0002
Revises: 0001
Create Date: 2026-02-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "secrets",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=255), unique=True, nullable=False),
        sa.Column("value_encrypted", sa.Text(), nullable=False),
        sa.Column("resource", sa.String(length=255), nullable=True),
        sa.Column("principal_id", sa.String(length=36), sa.ForeignKey("principals.id"), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_secrets_name", "secrets", ["name"])
    op.create_index("ix_secrets_resource", "secrets", ["resource"])


def downgrade() -> None:
    op.drop_index("ix_secrets_resource", table_name="secrets")
    op.drop_index("ix_secrets_name", table_name="secrets")
    op.drop_table("secrets")
