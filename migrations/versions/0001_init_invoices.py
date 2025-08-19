"""initial invoices table

Revision ID: 0001_init_invoices
Revises: 
Create Date: 2025-08-19 22:22:01
"""

from alembic import op
import sqlalchemy as sa

revision = '0001_init_invoices'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table('invoice',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('amount', sa.Float(), nullable=False),
        sa.Column('due_date', sa.Date(), nullable=False),
        sa.Column('paid', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

def downgrade() -> None:
    op.drop_table('invoice')
