"""merge ai analysis with existing schema

Revision ID: 9ff3d6b0ed4c
Revises: add_ai_analysis_table, e6a5cec87230
Create Date: 2025-09-27 13:42:06.327452+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9ff3d6b0ed4c'
down_revision = ('add_ai_analysis_table', 'e6a5cec87230')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
