"""add_purl_fields_to_components

Revision ID: 2ba89dbeb06f
Revises: de6cb7fc17f7
Create Date: 2026-11-11 05:29:17.344598

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2ba89dbeb06f'
down_revision = 'de6cb7fc17f7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('components', sa.Column('purl_type', sa.String(), nullable=True))
    op.add_column('components', sa.Column('purl_namespace', sa.String(), nullable=True))
    op.add_column('components', sa.Column('purl_name', sa.String(), nullable=True))
    op.create_index('ix_components_purl_type', 'components', ['purl_type'])
    op.create_index('ix_components_purl_namespace', 'components', ['purl_namespace'])
    op.create_index('ix_components_purl_name', 'components', ['purl_name'])


def downgrade() -> None:
    op.drop_index('ix_components_purl_name', table_name='components')
    op.drop_index('ix_components_purl_namespace', table_name='components')
    op.drop_index('ix_components_purl_type', table_name='components')
    op.drop_column('components', 'purl_name')
    op.drop_column('components', 'purl_namespace')
    op.drop_column('components', 'purl_type')
