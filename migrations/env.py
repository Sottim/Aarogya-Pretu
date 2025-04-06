import logging
from logging.config import fileConfig

from flask import current_app

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

# Import the SQLAlchemy db instance directly
from app import db
# Ensure models are imported so metadata is populated
from app import models

def get_engine():
    try:
        # this works with Flask-SQLAlchemy<3 and Alchemical
        return current_app.extensions['migrate'].db.get_engine()
    except (TypeError, AttributeError):
        # this works with Flask-SQLAlchemy>=3
        return current_app.extensions['migrate'].db.engine


def get_engine_url():
    try:
        return get_engine().url.render_as_string(hide_password=False).replace(
            '%', '%%')
    except AttributeError:
        return str(get_engine().url).replace('%', '%%')


# Set the target metadata directly from the imported db instance
# target_metadata = mymodel.Base.metadata
config.set_main_option('sqlalchemy.url', get_engine_url())
target_metadata = db.metadata # Use directly imported db metadata


# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, 
        target_metadata=target_metadata, # Use the directly set metadata
        literal_binds=True
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    # This callback is used to prevent an auto-migration from being generated
    # when there are no changes to the schema
    # reference: http://alembic.zzzcomputing.com/en/latest/cookbook.html
    def process_revision_directives(context, revision, directives):
        # This check is now implicitly handled by how we configure the context
        # based on whether it's autogenerate or not.
        # We mainly need this callback for the 'no changes detected' logic.
        if getattr(config.cmd_opts, 'autogenerate', False):
            script = directives[0]
            # Check if the upgrade operations are empty
            if script.upgrade_ops.is_empty():
                 directives[:] = []
                 logger.info('No changes in schema detected.')

    # Determine if we are in autogenerate mode
    is_autogenerate = getattr(config.cmd_opts, 'autogenerate', False)
    # Get configure_args regardless of mode, as it might be needed for both
    conf_args = current_app.extensions['migrate'].configure_args

    connectable = None
    if not is_autogenerate:
        # Connect only if we are NOT autogenerating (e.g., upgrade, sql)
        try:
            connectable = get_engine()
        except Exception as e:
            logger.error(f"Failed to get database engine: {e}")
            # Decide how to handle this - maybe raise or exit?
            # For now, let it proceed, it will likely fail later if connection needed
            pass # Or raise SystemExit("Database connection failed")

    if connectable:
        # === Run with Connection (for upgrade, downgrade, --sql) ===
        with connectable.connect() as connection:
            # If process_revision_directives is needed for execution phase, add it here
            # if conf_args.get("process_revision_directives") is None:
            #     conf_args["process_revision_directives"] = process_revision_directives

            context.configure(
                connection=connection,
                target_metadata=target_metadata, # Use the directly set metadata
                process_revision_directives=process_revision_directives, # Ensure it runs if needed
                **conf_args
            )

            with context.begin_transaction():
                context.run_migrations()
    else:
        # === Run without Connection (for autogenerate comparison) === 
        # Use the URL from the config (even if SQLite default)
        url = config.get_main_option("sqlalchemy.url")
        if not url:
             logger.error("sqlalchemy.url is not configured in alembic.ini or via Flask config.")
             raise SystemExit("Missing database configuration for offline migration.")

        logger.info(f"Running autogenerate comparison using URL: {url}")
        # Configure context for comparison. Alembic's revision command will use this.
        context.configure(
            url=url, # Configure with URL, not engine
            target_metadata=target_metadata, # Use the directly set metadata
            process_revision_directives=process_revision_directives,
            # compare_type=True, # Flask-Migrate sets this in configure_args
            # render_as_batch=True, # Recommended for SQLite compatibility, also likely in configure_args
            **conf_args
        )
        # Perform the comparison within a transaction <-- REMOVE THIS BLOCK
        # with context.begin_transaction():
        #    context.run_migrations(engine_name='compare') # Use dummy engine name
        # Alembic handles writing the script file if changes were detected
        # (i.e., if process_revision_directives didn't empty the directives)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
