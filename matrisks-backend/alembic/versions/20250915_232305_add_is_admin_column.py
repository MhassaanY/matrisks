"""add_is_admin_column

Revision ID: e6a5cec87230
Revises: 20250524_010430
Create Date: 2025-09-15 23:23:05.014636+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e6a5cec87230'
down_revision = '20250524_010430'
branch_labels = None
depends_on = None


def upgrade():
    # Add is_admin column to users table
    op.add_column('users', sa.Column('is_admin', sa.Boolean(), nullable=True, server_default='false'))


def downgrade():
    # Remove is_admin column from users table
    op.drop_column('users', 'is_admin')
