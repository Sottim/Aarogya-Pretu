"""Add email verification fields to User model

Revision ID: bf8ce63713f6
Revises: 06a6a727bdf4
Create Date: 2025-04-11 02:14:55.186752

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bf8ce63713f6'
down_revision = '06a6a727bdf4'
branch_labels = None
depends_on = None


def upgrade():
    # Add email verification fields
    op.add_column('user', sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('user', sa.Column('verification_token', sa.String(length=128), nullable=True))
    op.add_column('user', sa.Column('verification_token_expires', sa.DateTime(), nullable=True))
    op.create_unique_constraint(None, 'user', ['verification_token'])


def downgrade():
    # Remove email verification fields
    op.drop_constraint(None, 'user', type_='unique')
    op.drop_column('user', 'verification_token_expires')
    op.drop_column('user', 'verification_token')
    op.drop_column('user', 'is_verified')
