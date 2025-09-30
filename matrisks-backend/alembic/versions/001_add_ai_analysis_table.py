"""Add AI analysis results table

Revision ID: add_ai_analysis_table
Revises: 
Create Date: 2025-09-27 18:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = 'add_ai_analysis_table'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create ai_analysis_results table
    op.create_table('ai_analysis_results',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('apk_name', sa.String(length=500), nullable=False),
    sa.Column('file_size', sa.Integer(), nullable=True),
    sa.Column('prediction', sa.String(length=50), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('active_features_count', sa.Integer(), nullable=True),
    sa.Column('total_features', sa.Integer(), nullable=True),
    sa.Column('active_features', sa.JSON(), nullable=True),
    sa.Column('feature_summary', sa.JSON(), nullable=True),
    sa.Column('model_info', sa.JSON(), nullable=True),
    sa.Column('analysis_timestamp', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('scan_id', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_analysis_results_id'), 'ai_analysis_results', ['id'], unique=False)


def downgrade() -> None:
    # Drop ai_analysis_results table
    op.drop_index(op.f('ix_ai_analysis_results_id'), table_name='ai_analysis_results')
    op.drop_table('ai_analysis_results')
