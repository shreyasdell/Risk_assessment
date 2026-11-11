"""fix_schema_drift

Revision ID: 5dc9fc5e2806
Revises: 2ba89dbeb06f
Create Date: 2026-11-11 05:45:43.785874

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5dc9fc5e2806'
down_revision = '2ba89dbeb06f'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('component_cve', sa.Column('confidence', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('component_cve', 'confidence')
