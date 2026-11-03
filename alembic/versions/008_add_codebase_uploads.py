"""add codebase uploads table

Revision ID: 008
Revises: 007
Create Date: 2026-11-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'codebase_uploads',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('upload_id', sa.String(), unique=True, nullable=False),
        sa.Column('application_id', sa.Integer(), sa.ForeignKey('applications.id'), nullable=True),
        sa.Column('source_type', sa.String(), nullable=False),  # 'zip' or 'github'
        sa.Column('source_url', sa.String(), nullable=True),  # GitHub URL
        sa.Column('file_path', sa.String(), nullable=True),  # Path to stored ZIP file
        sa.Column('file_name', sa.String(), nullable=True),  # Original filename
        sa.Column('file_size', sa.BigInteger(), nullable=True),  # File size in bytes
        sa.Column('status', sa.String(), default='uploaded', nullable=False),  # uploaded, analyzing, completed, failed
        sa.Column('analysis_result', postgresql.JSON(), nullable=True),  # Analysis results
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('uploaded_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('analyzed_at', sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table('codebase_uploads')
