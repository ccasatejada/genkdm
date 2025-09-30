"""
Enhanced database connector for KDM management system.

This module provides the main database connection and configuration for the KDM system.
Uses the comprehensive schema defined in db.schema with proper connection management.
"""

import sqlite3
from pathlib import Path
from contextlib import contextmanager

from db.schema import KDMDatabase, get_database
from utils.utils import get_current_path


# Default database configuration
DEFAULT_DB_PATH = f"{get_current_path()}/db/kdm_system.sqlite"

# Global database instance (initialized on first use)
_db_instance = None


def get_connection():
    """
    Get a database connection using the KDM schema.

    Returns:
        sqlite3.Connection: Database connection with row factory enabled
    """
    global _db_instance
    if _db_instance is None:
        _db_instance = get_database()

    return _db_instance.get_connection()


@contextmanager
def get_cursor():
    """
    Context manager for database operations with automatic commit/rollback.

    Usage:
        with get_cursor() as cursor:
            cursor.execute("INSERT INTO...")
            # Automatically commits on success, rolls back on error

    Yields:
        sqlite3.Cursor: Database cursor
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def init_database(db_path: str = None, reset: bool = False):
    """
    Initialize the KDM database with complete schema.

    Args:
        db_path (str): Path to database file (optional)
        reset (bool): If True, reset existing database

    Returns:
        KDMDatabase: Database instance
    """
    global _db_instance

    if reset:
        from db.schema import reset_database
        _db_instance = reset_database(db_path)
    else:
        _db_instance = KDMDatabase(db_path)

    return _db_instance


def get_database_info():
    """
    Get comprehensive database information.

    Returns:
        dict: Database schema and statistics
    """
    global _db_instance
    if _db_instance is None:
        _db_instance = get_database()

    return _db_instance.get_schema_info()


# Legacy compatibility - maintain old interface
def get_legacy_connection():
    """
    Get legacy-style connection for backward compatibility.

    Returns:
        tuple: (connection, cursor) as in original connector
    """
    conn = sqlite3.connect(DEFAULT_DB_PATH)
    cursor = conn.cursor()
    return conn, cursor


# Initialize database on module import
if not Path(DEFAULT_DB_PATH).exists():
    print("🔄 Initializing KDM database on first use...")
    init_database()
else:
    _db_instance = get_database()


# For backward compatibility, expose conn and cursor
conn, cursor = get_legacy_connection()
