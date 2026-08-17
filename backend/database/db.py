from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event as sa_event

db = SQLAlchemy()


def configure_sqlite(db_instance):
    """Enables WAL journal mode and a busy timeout on every new SQLite
    connection. WAL allows concurrent readers while a writer commits;
    busy_timeout makes SQLite itself wait (instead of immediately raising
    "database is locked") if the simulator's background writer and a UI
    request collide. Complementary to ingest_service's own retry loop."""
    @sa_event.listens_for(db_instance.engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()
