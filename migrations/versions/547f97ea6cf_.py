"""empty message

Revision ID: 547f97ea6cf
Revises: d852d07fc6
Create Date: 2015-09-30 21:08:41.156501

"""

# revision identifiers, used by Alembic.
revision = '547f97ea6cf'
down_revision = 'd852d07fc6'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('about_me', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('last_seen', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('location', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('member_since', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('name', sa.String(length=64), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'name')
    op.drop_column('users', 'member_since')
    op.drop_column('users', 'location')
    op.drop_column('users', 'last_seen')
    op.drop_column('users', 'about_me')
    ### end Alembic commands ###
