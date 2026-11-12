"""Add canonical component identity layer

Revision ID: 010
Revises: 009_add_os_package_normalization
Create Date: 2025-01-13

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '010_add_canonical_identity_layer'
down_revision = '009_add_os_package_normalization'
branch_labels = None
depends_on = None


def upgrade():
    # Add canonical identity fields to components table
    op.add_column('components', sa.Column('canonical_ecosystem', sa.String(), nullable=True))
    op.add_column('components', sa.Column('canonical_vendor_identity', sa.String(), nullable=True))
    op.add_column('components', sa.Column('canonical_product_identity', sa.String(), nullable=True))
    op.add_column('components', sa.Column('canonical_key', sa.String(), nullable=True))
    
    # Create indexes for faster lookups
    op.create_index('ix_components_canonical_ecosystem', 'components', ['canonical_ecosystem'])
    op.create_index('ix_components_canonical_vendor_identity', 'components', ['canonical_vendor_identity'])
    op.create_index('ix_components_canonical_product_identity', 'components', ['canonical_product_identity'])
    op.create_index('ix_components_canonical_key', 'components', ['canonical_key'], unique=True)


def downgrade():
    # Drop indexes
    op.drop_index('ix_components_canonical_key', 'components')
    op.drop_index('ix_components_canonical_product_identity', 'components')
    op.drop_index('ix_components_canonical_vendor_identity', 'components')
    op.drop_index('ix_components_canonical_ecosystem', 'components')
    
    # Drop columns
    op.drop_column('components', 'canonical_key')
    op.drop_column('components', 'canonical_product_identity')
    op.drop_column('components', 'canonical_vendor_identity')
    op.drop_column('components', 'canonical_ecosystem')
