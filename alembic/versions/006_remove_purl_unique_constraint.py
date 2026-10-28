"""Remove unique constraint from purl to allow same component in multiple applications

Revision ID: 006
Revises: 005
Create Date: 2026-10-27

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade():
    # PostgreSQL: Use ALTER TABLE to drop the unique constraint directly
    # First, we need to drop the unique constraint on purl
    op.execute("ALTER TABLE components DROP CONSTRAINT IF EXISTS ix_components_purl")
    
    # Then drop the unique index if it exists
    op.execute("DROP INDEX IF EXISTS ix_components_purl")
    
    # Recreate the index without the unique constraint
    op.execute("CREATE INDEX ix_components_purl ON components (purl)")


def downgrade():
    # Re-add the unique constraint
    op.execute("DROP INDEX IF EXISTS ix_components_purl")
    op.execute("CREATE UNIQUE INDEX ix_components_purl ON components (purl)")
