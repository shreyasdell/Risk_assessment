"""Add user role for RBAC

Revision ID: 005
Revises: 004
Create Date: 2026-10-26

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade():
    # Add role column to users table
    op.add_column('users', sa.Column('role', sa.Enum('admin', 'analyst', 'viewer', name='userrole'), nullable=False, server_default='viewer'))
    
    # Set existing admin users to admin role
    op.execute("UPDATE users SET role = 'admin' WHERE is_admin = 1")


def downgrade():
    # Remove the role column
    op.drop_column('users', 'role')
