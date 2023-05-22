"""initial

Revision ID: 7d76a1307458
Revises: 
Create Date: 2023-05-22 16:23:30.012935

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7d76a1307458'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
    "users",
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("username", sa.String(50), nullable=False),
    sa.Column("email", sa.String(50), nullable=False),
    sa.Column("password_hash", sa.String(100), nullable=False)
)
    op.create_table(
    "tasks",
    sa.Column("id", sa.Integer, primary_key=True, index=True)
    sa.Column("user_id", sa.Integer, nullable=False)
    sa.Column("description", sa.String(255), nullable=False)
    sa.Column("status", sa.String(10), nullable=False)
)
    op.create_table(
    "deleted_tasks",
    sa.Column("id", sa.Integer, primary_key=True, index=True)
    sa.Column("user_id", sa.Integer, nullable=False)
    sa.Column("task_id", sa.Integer, nullable=False)
    sa.Column("description", sa.String(255), nullable=False)
    sa.Column("status", sa.String(10), nullable=False)
)


def downgrade() -> None:
    op.drop_table("deleted_tasks")
    op.drop_table("tasks")
    op.drop_table("users")
