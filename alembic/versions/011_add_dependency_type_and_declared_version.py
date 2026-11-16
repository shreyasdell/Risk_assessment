"""Add dependency_type and declared_version to components

Revision ID: 011_dep_type
Revises: 010_add_canonical_identity_layer
Create Date: 2025-01-13

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '011_dep_type'
down_revision = '010_add_canonical_identity_layer'
branch_labels = None
depends_on = None


def upgrade():
    # Add dependency_type and declared_version fields to components table
    op.add_column('components', sa.Column('dependency_type', sa.String(), nullable=True))
    op.add_column('components', sa.Column('declared_version', sa.String(), nullable=True))
    op.add_column('components', sa.Column('version_unresolved', sa.Boolean(), nullable=True, default=False))
    
    # Create index for dependency_type filtering
    op.create_index('ix_components_dependency_type', 'components', ['dependency_type'])


def downgrade():
    # Drop index
    op.drop_index('ix_components_dependency_type', 'components')
    
    # Drop columns
    op.drop_column('components', 'version_unresolved')
    op.drop_column('components', 'declared_version')
    op.drop_column('components', 'dependency_type')
