"""Add unique constraint on components

Revision ID: unique_components
Revises: 
Create Date: 2026-11-10 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'unique_components'
down_revision = None  # Will be set by alembic
branch_labels = None
depends_on = None


def upgrade():
    # Add unique constraint on (application_id, sbom_id, name, version)
    op.create_unique_constraint(
        'uq_application_sbom_name_version',
        'components',
        ['application_id', 'sbom_id', 'name', 'version']
    )


def downgrade():
    # Remove unique constraint
    op.drop_constraint(
        'uq_application_sbom_name_version',
        'components',
        type_='unique'
    )
