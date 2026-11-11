"""merge_heads

Revision ID: de6cb7fc17f7
Revises: 20261103_1000, unique_components
Create Date: 2026-11-11 04:49:18.761992

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'de6cb7fc17f7'
down_revision = ('20261103_1000', 'unique_components')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
