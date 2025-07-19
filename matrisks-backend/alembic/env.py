import os
import sys
from logging.config import fileConfig
from dotenv import load_dotenv

# Add the project root directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load environment variables
load_dotenv()

from alembic import context
from sqlalchemy import engine_from_config, pool
from app.database import SQLALCHEMY_DATABASE_URL, Base  # Changed from DATABASE_URL to SQLALCHEMY_DATABASE_URL

# this is the Alembic Config object
config = context.config

# Set the SQLAlchemy URL
config.set_main_option('sqlalchemy.url', SQLALCHEMY_DATABASE_URL)  # Updated this line

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
