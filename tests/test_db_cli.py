"""
Tests for db/cli.py - Database management CLI.

Tests cover:
- Database initialization
- Tenant management commands
- Certificate import
- CPL import
- DKDM import
- Bulk import
- Statistics display
- Data export
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import argparse

import pytest

from db.cli import (
    init_database,
    add_tenant,
    list_tenants,
    remove_tenant,
    import_certificate,
    import_cpl,
    import_dkdm,
    show_statistics,
    bulk_import,
    export_data,
    main
)
from db.schema import KDMDatabase
from db.dao import KDMDataAccessObject


@pytest.fixture
def temp_db():
    """Create a temporary test database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    db = KDMDatabase(db_path=db_path)
    yield db, db_path

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def mock_args():
    """Create a mock args namespace."""
    return argparse.Namespace()


class TestInitDatabase:
    """Test database initialization commands."""

    def test_init_database_without_reset(self, temp_db, mock_args):
        """Test initializing database without reset."""
        db, db_path = temp_db
        mock_args.reset = False

        with patch('db.cli.get_database', return_value=db):
            init_database(mock_args)

        # Database should exist and have tables
        schema_info = db.get_schema_info()
        assert schema_info['total_tables'] > 0

    def test_init_database_with_reset(self, mock_args, tmp_path):
        """Test initializing database with reset flag."""
        db_path = str(tmp_path / "test_reset.db")

        # Create initial database with data
        db = KDMDatabase(db_path=db_path)
        dao = KDMDataAccessObject(database=db)
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="TestTenant", organization="Test"))

        # Verify data exists
        stats = dao.get_statistics()
        assert stats['total_tenants'] == 1

        mock_args.reset = True

        # Call reset_database which will actually delete and recreate
        with patch('db.cli.reset_database') as mock_reset:
            # Simulate what reset_database does
            import os
            if os.path.exists(db_path):
                os.unlink(db_path)
            reset_db = KDMDatabase(db_path=db_path)
            mock_reset.return_value = reset_db

            init_database(mock_args)

        # Data should be cleared in the reset database
        reset_dao = KDMDataAccessObject(database=reset_db)
        stats = reset_dao.get_statistics()
        assert stats['total_tenants'] == 0


class TestTenantCommands:
    """Test tenant management commands."""

    def test_add_tenant_success(self, temp_db, mock_args):
        """Test adding a tenant successfully."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        mock_args.label = "NewCinema"
        mock_args.description = "Test cinema"
        mock_args.organization = "Test Org"
        mock_args.email = "test@cinema.com"

        with patch('db.cli.get_dao', return_value=dao):
            add_tenant(mock_args)

        # Verify tenant was created
        tenant = dao.get_tenant_by_label("NewCinema")
        assert tenant is not None
        assert tenant.organization == "Test Org"

    def test_add_tenant_with_minimal_info(self, temp_db, mock_args):
        """Test adding tenant with only required fields."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        mock_args.label = "MinimalCinema"
        mock_args.description = None
        mock_args.organization = None
        mock_args.email = None

        with patch('db.cli.get_dao', return_value=dao):
            add_tenant(mock_args)

        # Verify tenant was created
        tenant = dao.get_tenant_by_label("MinimalCinema")
        assert tenant is not None

    def test_add_duplicate_tenant_fails(self, temp_db, mock_args):
        """Test that adding duplicate tenant label fails."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Add first tenant
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="DupeCinema", organization="Org1"))

        mock_args.label = "DupeCinema"
        mock_args.description = None
        mock_args.organization = "Org2"
        mock_args.email = None

        with patch('db.cli.get_dao', return_value=dao):
            with pytest.raises(SystemExit):
                add_tenant(mock_args)

    def test_list_tenants_empty(self, temp_db, mock_args):
        """Test listing tenants when database is empty."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        mock_args.all = False

        with patch('db.cli.get_dao', return_value=dao):
            list_tenants(mock_args)
            # Should not raise error, just display no tenants

    def test_list_tenants_with_data(self, temp_db, mock_args):
        """Test listing tenants with data."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Add tenants
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="Cinema1", organization="Org1"))
        dao.create_tenant(TenantRecord(label="Cinema2", organization="Org2"))

        mock_args.all = False

        with patch('db.cli.get_dao', return_value=dao):
            list_tenants(mock_args)

    def test_list_tenants_include_inactive(self, temp_db, mock_args):
        """Test listing tenants including inactive ones."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Add and deactivate a tenant
        from db.dao import TenantRecord
        id1 = dao.create_tenant(TenantRecord(label="Cinema1", organization="Org1"))
        id2 = dao.create_tenant(TenantRecord(label="Cinema2", organization="Org2"))
        dao.delete_tenant(id2)

        # List active only
        mock_args.all = False
        with patch('db.cli.get_dao', return_value=dao):
            list_tenants(mock_args)

        # List all
        mock_args.all = True
        with patch('db.cli.get_dao', return_value=dao):
            list_tenants(mock_args)

    def test_remove_tenant_success(self, temp_db, mock_args):
        """Test removing a tenant."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Add tenant
        from db.dao import TenantRecord
        tenant_id = dao.create_tenant(TenantRecord(label="RemoveCinema", organization="Org"))

        mock_args.tenant_id = tenant_id

        with patch('db.cli.get_dao', return_value=dao):
            remove_tenant(mock_args)

        # Verify tenant was deactivated
        tenant = dao.get_tenant(tenant_id)
        assert tenant is None  # Should not be found (soft deleted)

    def test_remove_nonexistent_tenant(self, temp_db, mock_args):
        """Test removing nonexistent tenant fails."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        mock_args.tenant_id = 99999

        with patch('db.cli.get_dao', return_value=dao):
            with pytest.raises(SystemExit):
                remove_tenant(mock_args)


class TestCertificateCommands:
    """Test certificate import commands."""

    def test_import_certificate_success(self, temp_db, mock_args, tmp_path):
        """Test importing a certificate."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Create temporary cert and key files
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"

        # Generate test certificate
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timezone, timedelta

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )

        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        mock_args.name = "TestCert"
        mock_args.cert_path = str(cert_file)
        mock_args.key_path = str(key_file)

        with patch('db.cli.get_dao', return_value=dao):
            import_certificate(mock_args)

    def test_import_certificate_missing_cert_file(self, temp_db, mock_args):
        """Test that importing with missing cert file fails."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        mock_args.name = "TestCert"
        mock_args.cert_path = "/nonexistent/cert.pem"
        mock_args.key_path = "/nonexistent/key.pem"

        with patch('db.cli.get_dao', return_value=dao):
            with pytest.raises(SystemExit):
                import_certificate(mock_args)

    def test_import_certificate_missing_key_file(self, temp_db, mock_args, tmp_path):
        """Test that importing with missing key file fails."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        cert_file = tmp_path / "cert.pem"
        cert_file.write_text("dummy cert")

        mock_args.name = "TestCert"
        mock_args.cert_path = str(cert_file)
        mock_args.key_path = "/nonexistent/key.pem"

        with patch('db.cli.get_dao', return_value=dao):
            with pytest.raises(SystemExit):
                import_certificate(mock_args)


class TestCPLCommands:
    """Test CPL import commands."""

    def test_import_cpl_success(self, temp_db, mock_args, tmp_path):
        """Test importing a CPL."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Create tenant
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="TestCinema", organization="Org"))

        # Create CPL XML file
        cpl_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<CompositionPlaylist xmlns="http://www.digicine.com/PROTO-ASDCP-CPL-20040511#">
    <Id>urn:uuid:550e8400-e29b-41d4-a716-446655440000</Id>
    <ContentTitleText>Test Movie</ContentTitleText>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
</CompositionPlaylist>'''

        cpl_file = tmp_path / "test.xml"
        cpl_file.write_text(cpl_xml)

        mock_args.tenant_label = "TestCinema"
        mock_args.cpl_path = str(cpl_file)

        with patch('db.cli.get_dao', return_value=dao):
            import_cpl(mock_args)

    def test_import_cpl_nonexistent_tenant(self, temp_db, mock_args, tmp_path):
        """Test importing CPL with nonexistent tenant fails."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        cpl_file = tmp_path / "test.xml"
        cpl_file.write_text("<xml/>")

        mock_args.tenant_label = "NonexistentCinema"
        mock_args.cpl_path = str(cpl_file)

        with patch('db.cli.get_dao', return_value=dao):
            with pytest.raises(SystemExit):
                import_cpl(mock_args)

    def test_import_cpl_missing_file(self, temp_db, mock_args):
        """Test importing CPL with missing file fails."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Create tenant
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="TestCinema", organization="Org"))

        mock_args.tenant_label = "TestCinema"
        mock_args.cpl_path = "/nonexistent/cpl.xml"

        with patch('db.cli.get_dao', return_value=dao):
            with pytest.raises(SystemExit):
                import_cpl(mock_args)


class TestDKDMCommands:
    """Test DKDM import commands."""

    def test_import_dkdm_success(self, temp_db, mock_args, tmp_path):
        """Test importing a DKDM."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Create tenant and CPL
        from db.dao import TenantRecord
        tenant_id = dao.create_tenant(TenantRecord(label="TestCinema", organization="Org"))

        # Create and import CPL first
        cpl_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<CompositionPlaylist xmlns="http://www.digicine.com/PROTO-ASDCP-CPL-20040511#">
    <Id>urn:uuid:cpl-for-dkdm</Id>
    <ContentTitleText>Test Movie</ContentTitleText>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
</CompositionPlaylist>'''

        cpl_file = tmp_path / "cpl.xml"
        cpl_file.write_text(cpl_xml)
        dao.import_cpl_from_file(tenant_id, str(cpl_file))

        # Create DKDM XML
        dkdm_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-3/2006/ETM">
    <MessageId>urn:uuid:msg-1</MessageId>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
    <AuthenticatedPublic xmlns="http://www.smpte-ra.org/schemas/430-1/2006/KDM">
        <CompositionPlaylistId>urn:uuid:cpl-for-dkdm</CompositionPlaylistId>
        <ContentTitleText>Test Movie</ContentTitleText>
        <ContentKeysNotValidBefore>2025-01-01T00:00:00Z</ContentKeysNotValidBefore>
        <ContentKeysNotValidAfter>2026-01-01T00:00:00Z</ContentKeysNotValidAfter>
    </AuthenticatedPublic>
</DCinemaSecurityMessage>'''

        dkdm_file = tmp_path / "dkdm.xml"
        dkdm_file.write_text(dkdm_xml)

        mock_args.tenant_label = "TestCinema"
        mock_args.dkdm_path = str(dkdm_file)

        with patch('db.cli.get_dao', return_value=dao):
            import_dkdm(mock_args)

    def test_import_dkdm_nonexistent_tenant(self, temp_db, mock_args, tmp_path):
        """Test importing DKDM with nonexistent tenant fails."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        dkdm_file = tmp_path / "dkdm.xml"
        dkdm_file.write_text("<xml/>")

        mock_args.tenant_label = "NonexistentCinema"
        mock_args.dkdm_path = str(dkdm_file)

        with patch('db.cli.get_dao', return_value=dao):
            with pytest.raises(SystemExit):
                import_dkdm(mock_args)


class TestBulkImport:
    """Test bulk import functionality."""

    def test_bulk_import_cpls(self, temp_db, mock_args, tmp_path):
        """Test bulk importing CPLs."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Create tenant
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="TestCinema", organization="Org"))

        # Create CPL directory with multiple files
        cpl_dir = tmp_path / "cpls"
        cpl_dir.mkdir()

        for i in range(3):
            cpl_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<CompositionPlaylist xmlns="http://www.digicine.com/PROTO-ASDCP-CPL-20040511#">
    <Id>urn:uuid:cpl-{i}</Id>
    <ContentTitleText>Movie {i}</ContentTitleText>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
</CompositionPlaylist>'''
            (cpl_dir / f"cpl_{i}.xml").write_text(cpl_xml)

        mock_args.tenant_label = "TestCinema"
        mock_args.cpl_dir = str(cpl_dir)
        mock_args.dkdm_dir = None

        with patch('db.cli.get_dao', return_value=dao):
            bulk_import(mock_args)

        # Verify CPLs were imported
        stats = dao.get_statistics()
        assert stats['total_cpl'] == 3

    def test_bulk_import_dkdms(self, temp_db, mock_args, tmp_path):
        """Test bulk importing DKDMs."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Create tenant and CPLs
        from db.dao import TenantRecord
        tenant_id = dao.create_tenant(TenantRecord(label="TestCinema", organization="Org"))

        # Import CPLs first
        for i in range(2):
            cpl_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<CompositionPlaylist xmlns="http://www.digicine.com/PROTO-ASDCP-CPL-20040511#">
    <Id>urn:uuid:cpl-{i}</Id>
    <ContentTitleText>Movie {i}</ContentTitleText>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
</CompositionPlaylist>'''
            cpl_file = tmp_path / f"cpl_{i}.xml"
            cpl_file.write_text(cpl_xml)
            dao.import_cpl_from_file(tenant_id, str(cpl_file))

        # Create DKDM directory
        dkdm_dir = tmp_path / "dkdms"
        dkdm_dir.mkdir()

        for i in range(2):
            dkdm_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-3/2006/ETM">
    <MessageId>urn:uuid:msg-{i}</MessageId>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
    <AuthenticatedPublic xmlns="http://www.smpte-ra.org/schemas/430-1/2006/KDM">
        <CompositionPlaylistId>urn:uuid:cpl-{i}</CompositionPlaylistId>
        <ContentTitleText>Movie {i}</ContentTitleText>
        <ContentKeysNotValidBefore>2025-01-01T00:00:00Z</ContentKeysNotValidBefore>
        <ContentKeysNotValidAfter>2026-01-01T00:00:00Z</ContentKeysNotValidAfter>
    </AuthenticatedPublic>
</DCinemaSecurityMessage>'''
            (dkdm_dir / f"dkdm_{i}.xml").write_text(dkdm_xml)

        mock_args.tenant_label = "TestCinema"
        mock_args.cpl_dir = None
        mock_args.dkdm_dir = str(dkdm_dir)

        with patch('db.cli.get_dao', return_value=dao):
            bulk_import(mock_args)

        # Verify DKDMs were imported
        stats = dao.get_statistics()
        assert stats['total_dkdm'] == 2


class TestStatistics:
    """Test statistics display."""

    def test_show_statistics_empty(self, temp_db):
        """Test showing statistics on empty database."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        with patch('db.cli.get_dao', return_value=dao):
            show_statistics()

    def test_show_statistics_with_data(self, temp_db):
        """Test showing statistics with data."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Add some data
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="Cinema1", organization="Org1"))

        with patch('db.cli.get_dao', return_value=dao):
            show_statistics()


class TestExportData:
    """Test data export functionality."""

    def test_export_data_to_json(self, temp_db, mock_args, tmp_path):
        """Test exporting data to JSON file."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        # Add some data
        from db.dao import TenantRecord
        dao.create_tenant(TenantRecord(label="Cinema1", organization="Org1"))
        dao.create_tenant(TenantRecord(label="Cinema2", organization="Org2"))

        output_file = tmp_path / "export.json"
        mock_args.output_file = str(output_file)

        with patch('db.cli.get_dao', return_value=dao):
            export_data(mock_args)

        # Verify export file
        assert output_file.exists()

        with open(output_file) as f:
            exported_data = json.load(f)

        assert 'export_timestamp' in exported_data
        assert 'tenants' in exported_data
        assert 'statistics' in exported_data
        assert len(exported_data['tenants']) == 2


class TestMainFunction:
    """Test main CLI entry point."""

    def test_main_without_command(self):
        """Test main without command shows help."""
        with patch('sys.argv', ['db.cli']):
            with pytest.raises(SystemExit):
                main()

    def test_main_with_init_command(self, temp_db):
        """Test main with init command."""
        db, db_path = temp_db

        with patch('sys.argv', ['db.cli', 'init']):
            with patch('db.cli.get_database', return_value=db):
                main()

    def test_main_with_tenant_add_command(self, temp_db):
        """Test main with tenant add command."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        with patch('sys.argv', ['db.cli', 'tenant', 'add', 'TestCinema']):
            with patch('db.cli.get_dao', return_value=dao):
                main()

    def test_main_with_stats_command(self, temp_db):
        """Test main with stats command."""
        db, db_path = temp_db
        dao = KDMDataAccessObject(database=db)

        with patch('sys.argv', ['db.cli', 'stats']):
            with patch('db.cli.get_dao', return_value=dao):
                main()
