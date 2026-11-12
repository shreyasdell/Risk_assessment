"""Add CPE validation cache table

Revision ID: 20261112_0700
Revises: 5dc9fc5e2806
Create Date: 2026-11-12 07:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20261112_0700'
down_revision = '5dc9fc5e2806'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create cpe_validation_cache table
    op.create_table(
        'cpe_validation_cache',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('vendor', sa.String(), nullable=False),
        sa.Column('product', sa.String(), nullable=False),
        sa.Column('validation_status', sa.String(), nullable=False),
        sa.Column('checked_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('expires_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('hit_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cpe_validation_cache_vendor'), 'cpe_validation_cache', ['vendor'], unique=False)
    op.create_index(op.f('ix_cpe_validation_cache_product'), 'cpe_validation_cache', ['product'], unique=False)
    op.create_index('idx_vendor_product_unique', 'cpe_validation_cache', ['vendor', 'product'], unique=True)


def downgrade() -> None:
    op.drop_index('idx_vendor_product_unique', table_name='cpe_validation_cache')
    op.drop_index(op.f('ix_cpe_validation_cache_product'), table_name='cpe_validation_cache')
    op.drop_index(op.f('ix_cpe_validation_cache_vendor'), table_name='cpe_validation_cache')
    op.drop_table('cpe_validation_cache')
