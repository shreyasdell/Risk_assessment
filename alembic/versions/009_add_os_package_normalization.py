"""Add OS package normalization fields

Revision ID: 009
Revises: 20261112_0700
Create Date: 2025-01-13

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '009_add_os_package_normalization'
down_revision = '20261112_0700'
branch_labels = None
depends_on = None


def upgrade():
    # Add OS package normalization fields to components table
    op.add_column('components', sa.Column('package_ecosystem', sa.String(), nullable=True))
    op.add_column('components', sa.Column('canonical_vendor', sa.String(), nullable=True))
    op.add_column('components', sa.Column('canonical_product', sa.String(), nullable=True))
    
    # Create index on package_ecosystem for faster lookups
    op.create_index('ix_components_package_ecosystem', 'components', ['package_ecosystem'])


def downgrade():
    # Drop index
    op.drop_index('ix_components_package_ecosystem', 'components')
    
    # Drop columns
    op.drop_column('components', 'canonical_product')
    op.drop_column('components', 'canonical_vendor')
    op.drop_column('components', 'package_ecosystem')
