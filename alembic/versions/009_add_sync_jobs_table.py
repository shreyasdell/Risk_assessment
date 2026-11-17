"""add sync_jobs table

Revision ID: 009
Revises: 008
Create Date: 2026-11-17

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'sync_jobs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('application_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('total_components', sa.Integer(), nullable=False),
        sa.Column('processed_components', sa.Integer(), nullable=False),
        sa.Column('current_component', sa.String(), nullable=True),
        sa.Column('total_verified_cves', sa.Integer(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sync_jobs_application_id'), 'sync_jobs', ['application_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_sync_jobs_application_id'), table_name='sync_jobs')
    op.drop_table('sync_jobs')
