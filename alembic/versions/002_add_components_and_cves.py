"""Add components and CVEs tables

Revision ID: 002
Revises: 001
Create Date: 2026-10-14

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create components table
    op.create_table(
        'components',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('version', sa.String(), nullable=False),
        sa.Column('component_type', sa.Enum('library', 'framework', 'sdk', 'tool', 'platform', 'operating_system', 'database', 'other', name='componenttypeenum'), nullable=True),
        sa.Column('purl', sa.String(), nullable=True),
        sa.Column('supplier', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('license', sa.String(), nullable=True),
        sa.Column('cpe', sa.String(), nullable=True),
        sa.Column('application_id', sa.Integer(), nullable=True),
        sa.Column('sbom_id', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_components_id'), 'components', ['id'], unique=False)
    op.create_index(op.f('ix_components_name'), 'components', ['name'], unique=False)
    op.create_index(op.f('ix_components_version'), 'components', ['version'], unique=False)
    op.create_index(op.f('ix_components_purl'), 'components', ['purl'], unique=True)
    op.create_index(op.f('ix_components_sbom_id'), 'components', ['sbom_id'], unique=False)

    # Create cves table
    op.create_table(
        'cves',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(), nullable=True),
        sa.Column('severity', sa.Enum('none', 'low', 'medium', 'high', 'critical', name='severityenum'), nullable=True),
        sa.Column('cwe_id', sa.String(), nullable=True),
        sa.Column('published_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('modified_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('exploit_available', sa.Boolean(), nullable=True),
        sa.Column('patch_available', sa.Boolean(), nullable=True),
        sa.Column('references', sa.Text(), nullable=True),
        sa.Column('nvd_url', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cves_id'), 'cves', ['id'], unique=False)
    op.create_index(op.f('ix_cves_cve_id'), 'cves', ['cve_id'], unique=True)

    # Create component_cve association table
    op.create_table(
        'component_cve',
        sa.Column('component_id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['component_id'], ['components.id'], ),
        sa.ForeignKeyConstraint(['cve_id'], ['cves.id'], ),
        sa.PrimaryKeyConstraint('component_id', 'cve_id')
    )


def downgrade() -> None:
    op.drop_table('component_cve')
    op.drop_index(op.f('ix_cves_cve_id'), table_name='cves')
    op.drop_index(op.f('ix_cves_id'), table_name='cves')
    op.drop_table('cves')
    
    op.drop_index(op.f('ix_components_sbom_id'), table_name='components')
    op.drop_index(op.f('ix_components_purl'), table_name='components')
    op.drop_index(op.f('ix_components_version'), table_name='components')
    op.drop_index(op.f('ix_components_name'), table_name='components')
    op.drop_index(op.f('ix_components_id'), table_name='components')
    op.drop_table('components')
