"""Add risk, remediation, audit, and NIST tables

Revision ID: 003
Revises: 002
Create Date: 2026-10-14

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create risk_scores table
    op.create_table(
        'risk_scores',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('application_id', sa.Integer(), nullable=False),
        sa.Column('overall_score', sa.Float(), nullable=False),
        sa.Column('rating', sa.Enum('Low', 'Moderate', 'High', 'Very High', 'Critical', name='riskrating'), nullable=False),
        sa.Column('cvss_weighted', sa.Float(), nullable=True),
        sa.Column('criticality_weighted', sa.Float(), nullable=True),
        sa.Column('exposure_weighted', sa.Float(), nullable=True),
        sa.Column('exploit_weighted', sa.Float(), nullable=True),
        sa.Column('patch_delay_weighted', sa.Float(), nullable=True),
        sa.Column('vendor_risk_weighted', sa.Float(), nullable=True),
        sa.Column('total_cves_found', sa.Integer(), nullable=True),
        sa.Column('critical_cves_count', sa.Integer(), nullable=True),
        sa.Column('high_cves_count', sa.Integer(), nullable=True),
        sa.Column('medium_cves_count', sa.Integer(), nullable=True),
        sa.Column('low_cves_count', sa.Integer(), nullable=True),
        sa.Column('calculated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('calculated_by', sa.String(length=100), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_risk_scores_id'), 'risk_scores', ['id'], unique=False)
    op.create_index(op.f('ix_risk_scores_application_id'), 'risk_scores', ['application_id'], unique=False)

    # Create remediations table
    op.create_table(
        'remediations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('application_id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.Integer(), nullable=False),
        sa.Column('component_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.Enum('Open', 'In Progress', 'Mitigated', 'Resolved', 'Risk Accepted', 'False Positive', name='remediationstatus'), nullable=False),
        sa.Column('priority', sa.Enum('Critical', 'High', 'Medium', 'Low', name='remediationpriority'), nullable=False),
        sa.Column('assigned_to', sa.String(length=200), nullable=True),
        sa.Column('due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('recommended_action', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['cve_id'], ['cves.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['component_id'], ['components.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_remediations_id'), 'remediations', ['id'], unique=False)
    op.create_index(op.f('ix_remediations_application_id'), 'remediations', ['application_id'], unique=False)
    op.create_index(op.f('ix_remediations_cve_id'), 'remediations', ['cve_id'], unique=False)
    op.create_index(op.f('ix_remediations_status'), 'remediations', ['status'], unique=False)

    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('user_role', sa.String(length=50), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_id', sa.Integer(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_resource_type'), 'audit_logs', ['resource_type'], unique=False)
    op.create_index(op.f('ix_audit_logs_timestamp'), 'audit_logs', ['timestamp'], unique=False)

    # Create nist_recommendations table
    op.create_table(
        'nist_recommendations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cwe_id', sa.String(length=20), nullable=False),
        sa.Column('cwe_name', sa.String(length=200), nullable=True),
        sa.Column('nist_category', sa.String(length=100), nullable=True),
        sa.Column('nist_function', sa.String(length=50), nullable=True),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('detailed_guidance', sa.Text(), nullable=True),
        sa.Column('references', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cwe_id')
    )
    op.create_index(op.f('ix_nist_recommendations_id'), 'nist_recommendations', ['id'], unique=False)
    op.create_index(op.f('ix_nist_recommendations_cwe_id'), 'nist_recommendations', ['cwe_id'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_nist_recommendations_cwe_id'), table_name='nist_recommendations')
    op.drop_index(op.f('ix_nist_recommendations_id'), table_name='nist_recommendations')
    op.drop_table('nist_recommendations')

    op.drop_index(op.f('ix_audit_logs_timestamp'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_resource_type'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_user_id'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_id'), table_name='audit_logs')
    op.drop_table('audit_logs')

    op.drop_index(op.f('ix_remediations_status'), table_name='remediations')
    op.drop_index(op.f('ix_remediations_cve_id'), table_name='remediations')
    op.drop_index(op.f('ix_remediations_application_id'), table_name='remediations')
    op.drop_index(op.f('ix_remediations_id'), table_name='remediations')
    op.drop_table('remediations')

    op.drop_index(op.f('ix_risk_scores_application_id'), table_name='risk_scores')
    op.drop_index(op.f('ix_risk_scores_id'), table_name='risk_scores')
    op.drop_table('risk_scores')
