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
    # Add role column to users table with uppercase enum values
    op.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'VIEWER'")
    
    # Set existing admin users to admin role (PostgreSQL-compatible boolean comparison)
    op.execute("UPDATE users SET role = 'ADMIN' WHERE is_admin = TRUE")


def downgrade():
    # Remove the role column
    op.drop_column('users', 'role')
