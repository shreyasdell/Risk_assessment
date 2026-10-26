"""Add vendor enhancements

Revision ID: 004
Revises: 003
Create Date: 2026-10-26

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns to vendors table
    op.add_column('vendors', sa.Column('tier', sa.String(50), nullable=True))
    op.add_column('vendors', sa.Column('risk_score', sa.Float(), nullable=True))
    op.add_column('vendors', sa.Column('compliance_status', sa.String(50), nullable=True))


def downgrade():
    # Remove the columns
    op.drop_column('vendors', 'compliance_status')
    op.drop_column('vendors', 'risk_score')
    op.drop_column('vendors', 'tier')
