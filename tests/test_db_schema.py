"""
Tests for db/schema.py - Database schema and initialization.

Tests cover:
- Database initialization
- Table creation
- Foreign key constraints
- Index creation
- Schema information retrieval
- Database reset functionality
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from db.schema import KDMDatabase, get_database, reset_database


@pytest.fixture
def temp_db_path():
    """Create a temporary database path for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def test_db(temp_db_path):
    """Create a test database instance."""
    return KDMDatabase(db_path=temp_db_path)


class TestDatabaseInitialization:
    """Test database initialization and setup."""

    def test_database_file_created(self, temp_db_path):
        """Test that database file is created on initialization."""
        db = KDMDatabase(db_path=temp_db_path)
        assert Path(temp_db_path).exists()

    def test_database_directory_created(self):
        """Test that database directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = f"{tmpdir}/subdir/test.db"
            db = KDMDatabase(db_path=db_path)
            assert Path(db_path).exists()
            assert Path(db_path).parent.exists()

    def test_all_tables_created(self, test_db):
        """Test that all required tables are created."""
        expected_tables = [
            "tenants",
            "self_signed_certificates",
            "certificate_chains",
            "cpl",
            "dkdm",
            "kdm_generated"
        ]

        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        for table in expected_tables:
            assert table in tables, f"Table '{table}' not created"


class TestForeignKeyConstraints:
    """Test foreign key constraint enforcement."""

    def test_foreign_keys_enabled(self, test_db):
        """Test that foreign keys are enabled in connections."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys")
            result = cursor.fetchone()[0]
            assert result == 1, "Foreign keys are not enabled"

    def test_foreign_key_constraint_on_certificate_chains(self, test_db):
        """Test that certificate_chains requires valid tenant_id."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()

            # Try to insert certificate chain with invalid tenant_id
            with pytest.raises(sqlite3.IntegrityError):
                cursor.execute('''
                    INSERT INTO certificate_chains (
                        tenant_id, chain_name, root_cert_path, signer_cert_path,
                        device_cert_path, root_thumbprint, signer_thumbprint,
                        device_thumbprint, chain_valid_from, chain_valid_until
                    ) VALUES (9999, 'test', 'path1', 'path2', 'path3', 'thumb1', 'thumb2', 'thumb3',
                              '2025-01-01', '2026-01-01')
                ''')
                conn.commit()

    def test_foreign_key_constraint_on_cpl(self, test_db):
        """Test that cpl requires valid tenant_id."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()

            # Try to insert CPL with invalid tenant_id
            with pytest.raises(sqlite3.IntegrityError):
                cursor.execute('''
                    INSERT INTO cpl (
                        tenant_id, cpl_uuid, cpl_file_path, content_title_text, issue_date
                    ) VALUES (9999, 'uuid-1', '/path/to/cpl.xml', 'Test CPL', '2025-01-01')
                ''')
                conn.commit()

    def test_foreign_key_constraint_on_dkdm(self, test_db):
        """Test that dkdm requires valid tenant_id and cpl_id."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()

            # Try to insert DKDM with invalid tenant_id
            with pytest.raises(sqlite3.IntegrityError):
                cursor.execute('''
                    INSERT INTO dkdm (
                        tenant_id, cpl_id, dkdm_uuid, dkdm_file_path, message_id,
                        content_title_text, composition_playlist_id,
                        content_keys_not_valid_before, content_keys_not_valid_after,
                        issue_date, signer_issuer_name, signer_serial_number, key_ids_json
                    ) VALUES (9999, 9999, 'uuid-1', '/path', 'msg-1', 'Title', 'cpl-uuid',
                              '2025-01-01', '2026-01-01', '2025-01-01', 'Issuer', '12345', '[]')
                ''')
                conn.commit()

    def test_foreign_key_cascade_behavior(self, test_db):
        """Test foreign key behavior when parent records exist."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()

            # Create a tenant
            cursor.execute('''
                INSERT INTO tenants (label, description, organization)
                VALUES ('TestTenant', 'Test', 'TestOrg')
            ''')
            tenant_id = cursor.lastrowid
            conn.commit()

            # Create CPL with valid tenant_id
            cursor.execute('''
                INSERT INTO cpl (
                    tenant_id, cpl_uuid, cpl_file_path, content_title_text, issue_date
                ) VALUES (?, 'uuid-1', '/path/to/cpl.xml', 'Test CPL', '2025-01-01')
            ''', (tenant_id,))
            conn.commit()

            # Verify CPL was created
            cursor.execute('SELECT COUNT(*) FROM cpl WHERE tenant_id = ?', (tenant_id,))
            assert cursor.fetchone()[0] == 1


class TestTableStructure:
    """Test table structures and constraints."""

    def test_tenants_table_structure(self, test_db):
        """Test tenants table has required columns."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(tenants)")
            columns = {row[1]: row[2] for row in cursor.fetchall()}

        required_columns = {
            'id': 'INTEGER',
            'label': 'TEXT',
            'description': 'TEXT',
            'organization': 'TEXT',
            'contact_email': 'TEXT',
            'created_at': 'TIMESTAMP',
            'updated_at': 'TIMESTAMP',
            'is_active': 'BOOLEAN'
        }

        for col_name, col_type in required_columns.items():
            assert col_name in columns, f"Column '{col_name}' missing from tenants table"
            assert columns[col_name] == col_type, f"Column '{col_name}' has wrong type"

    def test_tenants_label_unique_constraint(self, test_db):
        """Test that tenant label must be unique."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()

            # Insert first tenant
            cursor.execute('''
                INSERT INTO tenants (label, description, organization)
                VALUES ('UniqueLabel', 'Test1', 'Org1')
            ''')
            conn.commit()

            # Try to insert duplicate label
            with pytest.raises(sqlite3.IntegrityError):
                cursor.execute('''
                    INSERT INTO tenants (label, description, organization)
                    VALUES ('UniqueLabel', 'Test2', 'Org2')
                ''')
                conn.commit()

    def test_self_signed_certificates_unique_constraints(self, test_db):
        """Test unique constraints on certificates."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()

            # Insert first certificate
            cursor.execute('''
                INSERT INTO self_signed_certificates (
                    certificate_name, certificate_path, private_key_path,
                    subject_name, issuer_name, serial_number, thumbprint,
                    not_valid_before, not_valid_after
                ) VALUES ('Cert1', '/path/cert1.pem', '/path/key1.pem',
                          'CN=Test', 'CN=Test', '12345', 'thumbprint1',
                          '2025-01-01', '2026-01-01')
            ''')
            conn.commit()

            # Try to insert duplicate certificate_path
            with pytest.raises(sqlite3.IntegrityError):
                cursor.execute('''
                    INSERT INTO self_signed_certificates (
                        certificate_name, certificate_path, private_key_path,
                        subject_name, issuer_name, serial_number, thumbprint,
                        not_valid_before, not_valid_after
                    ) VALUES ('Cert2', '/path/cert1.pem', '/path/key2.pem',
                              'CN=Test2', 'CN=Test2', '67890', 'thumbprint2',
                              '2025-01-01', '2026-01-01')
                ''')
                conn.commit()

    def test_cpl_uuid_unique_constraint(self, test_db):
        """Test that CPL UUID must be unique."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()

            # Create tenant first
            cursor.execute('''
                INSERT INTO tenants (label, description, organization)
                VALUES ('Tenant1', 'Test', 'Org')
            ''')
            tenant_id = cursor.lastrowid
            conn.commit()

            # Insert first CPL
            cursor.execute('''
                INSERT INTO cpl (
                    tenant_id, cpl_uuid, cpl_file_path, content_title_text, issue_date
                ) VALUES (?, 'same-uuid', '/path1.xml', 'CPL1', '2025-01-01')
            ''', (tenant_id,))
            conn.commit()

            # Try to insert duplicate UUID
            with pytest.raises(sqlite3.IntegrityError):
                cursor.execute('''
                    INSERT INTO cpl (
                        tenant_id, cpl_uuid, cpl_file_path, content_title_text, issue_date
                    ) VALUES (?, 'same-uuid', '/path2.xml', 'CPL2', '2025-01-01')
                ''', (tenant_id,))
                conn.commit()


class TestIndexCreation:
    """Test that indexes are created for performance."""

    def test_tenant_indexes_created(self, test_db):
        """Test that tenant-related indexes exist."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name FROM sqlite_master
                WHERE type='index' AND tbl_name='tenants'
            ''')
            indexes = [row[0] for row in cursor.fetchall()]

        assert 'idx_tenants_label' in indexes
        assert 'idx_tenants_active' in indexes

    def test_cpl_indexes_created(self, test_db):
        """Test that CPL-related indexes exist."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name FROM sqlite_master
                WHERE type='index' AND tbl_name='cpl'
            ''')
            indexes = [row[0] for row in cursor.fetchall()]

        assert 'idx_cpl_tenant' in indexes
        assert 'idx_cpl_uuid' in indexes
        assert 'idx_cpl_active' in indexes

    def test_dkdm_indexes_created(self, test_db):
        """Test that DKDM-related indexes exist."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT name FROM sqlite_master
                WHERE type='index' AND tbl_name='dkdm'
            ''')
            indexes = [row[0] for row in cursor.fetchall()]

        assert 'idx_dkdm_tenant' in indexes
        assert 'idx_dkdm_cpl' in indexes
        assert 'idx_dkdm_uuid' in indexes


class TestSchemaInfo:
    """Test schema information retrieval."""

    def test_get_schema_info_returns_dict(self, test_db):
        """Test that get_schema_info returns proper dictionary."""
        schema_info = test_db.get_schema_info()

        assert isinstance(schema_info, dict)
        assert 'database_path' in schema_info
        assert 'tables' in schema_info
        assert 'total_tables' in schema_info

    def test_schema_info_includes_all_tables(self, test_db):
        """Test that schema info includes all expected tables."""
        schema_info = test_db.get_schema_info()

        expected_tables = [
            'tenants', 'self_signed_certificates', 'certificate_chains',
            'cpl', 'dkdm', 'kdm_generated'
        ]

        for table in expected_tables:
            assert table in schema_info['tables']

    def test_schema_info_includes_column_details(self, test_db):
        """Test that schema info includes column details."""
        schema_info = test_db.get_schema_info()

        tenants_info = schema_info['tables']['tenants']
        assert 'columns' in tenants_info
        assert 'row_count' in tenants_info
        assert len(tenants_info['columns']) > 0

        # Check column structure
        first_column = tenants_info['columns'][0]
        assert 'name' in first_column
        assert 'type' in first_column
        assert 'pk' in first_column

    def test_schema_info_row_count_accurate(self, test_db):
        """Test that row count in schema info is accurate."""
        # Insert some test data
        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tenants (label, description, organization)
                VALUES ('Tenant1', 'Test', 'Org')
            ''')
            cursor.execute('''
                INSERT INTO tenants (label, description, organization)
                VALUES ('Tenant2', 'Test', 'Org')
            ''')
            conn.commit()

        schema_info = test_db.get_schema_info()
        assert schema_info['tables']['tenants']['row_count'] == 2


class TestDatabaseReset:
    """Test database reset functionality."""

    def test_reset_database_removes_old_file(self, temp_db_path):
        """Test that reset_database removes existing database file."""
        # Create initial database
        db1 = KDMDatabase(db_path=temp_db_path)

        # Add some data
        with db1.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tenants (label, description, organization)
                VALUES ('Tenant1', 'Test', 'Org')
            ''')
            conn.commit()

        # Reset database
        db2 = reset_database(db_path=temp_db_path)

        # Verify data is gone
        with db2.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM tenants')
            assert cursor.fetchone()[0] == 0

    def test_reset_database_recreates_schema(self, temp_db_path):
        """Test that reset_database recreates all tables."""
        # Create and reset database
        KDMDatabase(db_path=temp_db_path)
        db = reset_database(db_path=temp_db_path)

        # Verify all tables exist
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

        expected_tables = [
            'tenants', 'self_signed_certificates', 'certificate_chains',
            'cpl', 'dkdm', 'kdm_generated'
        ]

        for table in expected_tables:
            assert table in tables


class TestConnectionContextManager:
    """Test database connection context manager."""

    def test_connection_context_manager_closes(self, test_db):
        """Test that connection is properly closed after context."""
        conn = None
        with test_db.get_connection() as c:
            conn = c
            cursor = c.cursor()
            cursor.execute("SELECT 1")

        # Connection should be closed after context
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

    def test_connection_returns_dict_rows(self, test_db):
        """Test that connections return dict-like rows."""
        with test_db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tenants (label, description, organization)
                VALUES ('TestTenant', 'Test', 'TestOrg')
            ''')
            conn.commit()

            cursor.execute('SELECT * FROM tenants WHERE label = ?', ('TestTenant',))
            row = cursor.fetchone()

            # Should be able to access by column name
            assert row['label'] == 'TestTenant'
            assert row['organization'] == 'TestOrg'


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_get_database_returns_instance(self):
        """Test that get_database returns KDMDatabase instance."""
        db = get_database()
        assert isinstance(db, KDMDatabase)
        assert Path(db.db_path).exists()

    def test_get_database_creates_default_path(self):
        """Test that get_database uses default path."""
        db = get_database()
        assert 'genkdmdb.sql' in db.db_path
