"""Add CVE Filter Agent fields to CVE model

Revision ID: 007
Revises: 006
Create Date: 2026-10-30

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade():
    """Add agent-related columns to CVE table."""
    op.add_column('cves', sa.Column('agent_confidence', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('cves', sa.Column('agent_verdict', sa.String(length=20), nullable=False, server_default='UNPROCESSED'))
    op.add_column('cves', sa.Column('agent_reasoning', sa.Text(), nullable=True))
    op.add_column('cves', sa.Column('match_method', sa.String(length=50), nullable=True))
    op.add_column('cves', sa.Column('stage_details', postgresql.JSON(), nullable=True))
    op.add_column('cves', sa.Column('is_false_positive', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('cves', sa.Column('agent_processing_time', sa.Float(), nullable=True))
    op.add_column('cves', sa.Column('agent_processed_at', sa.DateTime(), nullable=True))

    # Create indexes for filtering
    op.create_index('ix_cves_agent_confidence', 'cves', ['agent_confidence'])
    op.create_index('ix_cves_agent_verdict', 'cves', ['agent_verdict'])
    op.create_index('ix_cves_is_false_positive', 'cves', ['is_false_positive'])


def downgrade():
    """Remove agent-related columns from CVE table."""
    op.drop_index('ix_cves_is_false_positive', table_name='cves')
    op.drop_index('ix_cves_agent_verdict', table_name='cves')
    op.drop_index('ix_cves_agent_confidence', table_name='cves')

    op.drop_column('cves', 'agent_processed_at')
    op.drop_column('cves', 'agent_processing_time')
    op.drop_column('cves', 'is_false_positive')
    op.drop_column('cves', 'stage_details')
    op.drop_column('cves', 'match_method')
    op.drop_column('cves', 'agent_reasoning')
    op.drop_column('cves', 'agent_verdict')
    op.drop_column('cves', 'agent_confidence')
