"""Add LangGraph agent enrichment fields to components and vendor cache table

Revision ID: 20261103_1000
Revises: 745c6b5aa3ef
Create Date: 2026-11-03 10:00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20261103_1000'
down_revision = '745c6b5aa3ef'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to components table
    op.add_column('components', sa.Column('nvd_vendor', sa.String(), nullable=True))
    op.add_column('components', sa.Column('nvd_product', sa.String(), nullable=True))
    op.add_column('components', sa.Column('search_name', sa.String(), nullable=True))
    op.add_column('components', sa.Column('clean_version', sa.String(), nullable=True))
    op.add_column('components', sa.Column('constructed_cpe', sa.String(), nullable=True))
    op.add_column('components', sa.Column('ecosystem', sa.String(), nullable=True))
    op.add_column('components', sa.Column('enrichment_status', sa.String(), nullable=True, server_default='pending'))
    op.add_column('components', sa.Column('enrichment_confidence', sa.Integer(), nullable=True))
    op.add_column('components', sa.Column('enrichment_method', sa.String(), nullable=True))
    
    # Create indexes for new columns
    op.create_index('ix_components_nvd_vendor', 'components', ['nvd_vendor'])
    op.create_index('ix_components_nvd_product', 'components', ['nvd_product'])
    op.create_index('ix_components_search_name', 'components', ['search_name'])
    op.create_index('ix_components_ecosystem', 'components', ['ecosystem'])
    
    # Create vendor_product_cache table
    op.create_table(
        'vendor_product_cache',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('component_name', sa.String(), nullable=False),
        sa.Column('nvd_vendor', sa.String(), nullable=False),
        sa.Column('nvd_product', sa.String(), nullable=False),
        sa.Column('ecosystem', sa.String(), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=False),
        sa.Column('resolution_method', sa.String(), nullable=False),
        sa.Column('source_purl', sa.String(), nullable=True),
        sa.Column('hit_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.text('now()')),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_vendor_product_cache_component_name', 'vendor_product_cache', ['component_name'])
    op.create_index('ix_vendor_product_cache_nvd_vendor', 'vendor_product_cache', ['nvd_vendor'])
    op.create_index('ix_vendor_product_cache_nvd_product', 'vendor_product_cache', ['nvd_product'])
    op.create_index('ix_vendor_product_cache_ecosystem', 'vendor_product_cache', ['ecosystem'])
    op.create_index('idx_component_ecosystem', 'vendor_product_cache', ['component_name', 'ecosystem'])
    op.create_index('idx_vendor_product', 'vendor_product_cache', ['nvd_vendor', 'nvd_product'])


def downgrade():
    # Drop vendor_product_cache table
    op.drop_index('idx_vendor_product', table_name='vendor_product_cache')
    op.drop_index('idx_component_ecosystem', table_name='vendor_product_cache')
    op.drop_index('ix_vendor_product_cache_ecosystem', table_name='vendor_product_cache')
    op.drop_index('ix_vendor_product_cache_nvd_product', table_name='vendor_product_cache')
    op.drop_index('ix_vendor_product_cache_nvd_vendor', table_name='vendor_product_cache')
    op.drop_index('ix_vendor_product_cache_component_name', table_name='vendor_product_cache')
    op.drop_table('vendor_product_cache')
    
    # Drop indexes from components
    op.drop_index('ix_components_ecosystem', table_name='components')
    op.drop_index('ix_components_search_name', table_name='components')
    op.drop_index('ix_components_nvd_product', table_name='components')
    op.drop_index('ix_components_nvd_vendor', table_name='components')
    
    # Drop columns from components table
    op.drop_column('components', 'enrichment_method')
    op.drop_column('components', 'enrichment_confidence')
    op.drop_column('components', 'enrichment_status')
    op.drop_column('components', 'ecosystem')
    op.drop_column('components', 'constructed_cpe')
    op.drop_column('components', 'clean_version')
    op.drop_column('components', 'search_name')
    op.drop_column('components', 'nvd_product')
    op.drop_column('components', 'nvd_vendor')
