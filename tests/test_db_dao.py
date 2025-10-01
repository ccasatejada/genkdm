"""
Tests for db/dao.py - Data Access Object layer.

Tests cover:
- Tenant CRUD operations
- Certificate import and management
- CPL import from XML files
- DKDM import from XML files
- KDM generation records
- Statistics and reporting
"""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from lxml import etree

from db.dao import (
    KDMDataAccessObject,
    TenantRecord,
    SelfSignedCertificateRecord,
    CPLRecord,
    DKDMRecord,
    KDMGeneratedRecord,
    get_dao
)
from db.schema import KDMDatabase


@pytest.fixture
def temp_db():
    """Create a temporary test database."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    db = KDMDatabase(db_path=db_path)
    yield db

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def test_dao(temp_db):
    """Create a test DAO instance."""
    return KDMDataAccessObject(database=temp_db)


@pytest.fixture
def sample_tenant():
    """Create a sample tenant record."""
    return TenantRecord(
        label="TestCinema",
        description="Test cinema for unit tests",
        organization="Test Organization",
        contact_email="test@cinema.com"
    )


@pytest.fixture
def sample_cert():
    """Create a sample certificate record."""
    return SelfSignedCertificateRecord(
        certificate_name="TestCert",
        certificate_path="/path/to/cert.pem",
        private_key_path="/path/to/key.pem",
        certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        private_key_pem="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
        subject_name="CN=Test",
        issuer_name="CN=Test",
        serial_number="12345",
        thumbprint="test_thumbprint",
        not_valid_before=datetime(2025, 1, 1),
        not_valid_after=datetime(2026, 1, 1),
        certificate_role="ROOT"
    )


class TestTenantOperations:
    """Test tenant CRUD operations."""

    def test_create_tenant(self, test_dao, sample_tenant):
        """Test creating a new tenant."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        assert tenant_id > 0
        assert isinstance(tenant_id, int)

    def test_get_tenant_by_id(self, test_dao, sample_tenant):
        """Test retrieving tenant by ID."""
        tenant_id = test_dao.create_tenant(sample_tenant)
        retrieved_tenant = test_dao.get_tenant(tenant_id)

        assert retrieved_tenant is not None
        assert retrieved_tenant.id == tenant_id
        assert retrieved_tenant.label == sample_tenant.label
        assert retrieved_tenant.organization == sample_tenant.organization
        assert retrieved_tenant.contact_email == sample_tenant.contact_email

    def test_get_tenant_by_label(self, test_dao, sample_tenant):
        """Test retrieving tenant by label."""
        test_dao.create_tenant(sample_tenant)
        retrieved_tenant = test_dao.get_tenant_by_label(sample_tenant.label)

        assert retrieved_tenant is not None
        assert retrieved_tenant.label == sample_tenant.label

    def test_get_nonexistent_tenant_returns_none(self, test_dao):
        """Test that getting nonexistent tenant returns None."""
        tenant = test_dao.get_tenant(99999)
        assert tenant is None

    def test_list_tenants_empty(self, test_dao):
        """Test listing tenants when database is empty."""
        tenants = test_dao.list_tenants()
        assert len(tenants) == 0

    def test_list_tenants_with_data(self, test_dao):
        """Test listing tenants with data."""
        # Create multiple tenants
        tenant1 = TenantRecord(label="Cinema1", organization="Org1")
        tenant2 = TenantRecord(label="Cinema2", organization="Org2")
        tenant3 = TenantRecord(label="Cinema3", organization="Org3")

        test_dao.create_tenant(tenant1)
        test_dao.create_tenant(tenant2)
        test_dao.create_tenant(tenant3)

        tenants = test_dao.list_tenants()
        assert len(tenants) == 3

    def test_list_tenants_active_only(self, test_dao):
        """Test listing only active tenants."""
        # Create tenants
        tenant1 = TenantRecord(label="Cinema1", organization="Org1")
        tenant2 = TenantRecord(label="Cinema2", organization="Org2")

        id1 = test_dao.create_tenant(tenant1)
        id2 = test_dao.create_tenant(tenant2)

        # Deactivate one
        test_dao.delete_tenant(id2)

        # List active only
        active_tenants = test_dao.list_tenants(active_only=True)
        assert len(active_tenants) == 1
        assert active_tenants[0].id == id1

        # List all
        all_tenants = test_dao.list_tenants(active_only=False)
        assert len(all_tenants) == 2

    def test_update_tenant(self, test_dao, sample_tenant):
        """Test updating tenant information."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        # Update tenant
        updated_tenant = test_dao.get_tenant(tenant_id)
        updated_tenant.description = "Updated description"
        updated_tenant.contact_email = "updated@cinema.com"

        result = test_dao.update_tenant(updated_tenant)
        assert result is True

        # Verify update
        retrieved = test_dao.get_tenant(tenant_id)
        assert retrieved.description == "Updated description"
        assert retrieved.contact_email == "updated@cinema.com"

    def test_update_nonexistent_tenant(self, test_dao):
        """Test updating nonexistent tenant returns False."""
        tenant = TenantRecord(id=99999, label="Nonexistent")
        result = test_dao.update_tenant(tenant)
        assert result is False

    def test_delete_tenant_soft_delete(self, test_dao, sample_tenant):
        """Test that delete is a soft delete."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        # Delete tenant
        result = test_dao.delete_tenant(tenant_id)
        assert result is True

        # Tenant should not be found by active search
        tenant = test_dao.get_tenant(tenant_id)
        assert tenant is None

        # But should be in database
        with test_dao.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT is_active FROM tenants WHERE id = ?', (tenant_id,))
            row = cursor.fetchone()
            assert row is not None
            assert row[0] == 0  # is_active = False

    def test_tenant_label_unique_constraint(self, test_dao, sample_tenant):
        """Test that tenant label must be unique."""
        test_dao.create_tenant(sample_tenant)

        # Try to create duplicate
        duplicate = TenantRecord(label=sample_tenant.label, organization="Different Org")

        with pytest.raises(Exception):  # Should raise database integrity error
            test_dao.create_tenant(duplicate)


class TestCertificateOperations:
    """Test certificate operations."""

    def test_create_self_signed_certificate(self, test_dao, sample_cert):
        """Test creating a self-signed certificate record."""
        cert_id = test_dao.create_self_signed_certificate(sample_cert)

        assert cert_id > 0
        assert isinstance(cert_id, int)

    def test_certificate_unique_thumbprint(self, test_dao, sample_cert):
        """Test that certificate thumbprint must be unique."""
        test_dao.create_self_signed_certificate(sample_cert)

        # Try to create duplicate
        duplicate_cert = SelfSignedCertificateRecord(
            certificate_name="DuplicateCert",
            certificate_path="/different/path/cert.pem",
            private_key_path="/different/path/key.pem",
            certificate_pem="different pem",
            private_key_pem="different key",
            subject_name="CN=Different",
            issuer_name="CN=Different",
            serial_number="67890",
            thumbprint=sample_cert.thumbprint,  # Same thumbprint
            not_valid_before=datetime(2025, 1, 1),
            not_valid_after=datetime(2026, 1, 1)
        )

        with pytest.raises(Exception):
            test_dao.create_self_signed_certificate(duplicate_cert)

    def test_import_certificate_from_file(self, test_dao, tmp_path):
        """Test importing certificate from PEM files."""
        # Create temporary certificate and key files
        cert_file = tmp_path / "test_cert.pem"
        key_file = tmp_path / "test_key.pem"

        # Generate a simple self-signed certificate for testing
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from datetime import timedelta

        # Generate key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate")
        ])

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

        # Write files
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

        # Import certificate
        cert_id = test_dao.import_certificate_from_file(
            str(cert_file),
            str(key_file),
            "Imported Test Cert"
        )

        assert cert_id > 0


class TestCPLOperations:
    """Test CPL operations."""

    def test_create_cpl(self, test_dao, sample_tenant):
        """Test creating a CPL record."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        cpl = CPLRecord(
            tenant_id=tenant_id,
            cpl_uuid="550e8400-e29b-41d4-a716-446655440000",
            cpl_file_path="/path/to/cpl.xml",
            content_title_text="Test Movie",
            issue_date=datetime.now(timezone.utc),
            reel_count=2,
            key_ids_json='[{"key_id": "key1", "key_type": "MDIK"}]'
        )

        cpl_id = test_dao.create_cpl(cpl)
        assert cpl_id > 0

    def test_get_cpl_by_uuid(self, test_dao, sample_tenant):
        """Test retrieving CPL by UUID."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        cpl_uuid = "550e8400-e29b-41d4-a716-446655440000"
        cpl = CPLRecord(
            tenant_id=tenant_id,
            cpl_uuid=cpl_uuid,
            cpl_file_path="/path/to/cpl.xml",
            content_title_text="Test Movie",
            issue_date=datetime.now(timezone.utc)
        )

        test_dao.create_cpl(cpl)
        retrieved_cpl = test_dao.get_cpl_by_uuid(cpl_uuid)

        assert retrieved_cpl is not None
        assert retrieved_cpl.cpl_uuid == cpl_uuid
        assert retrieved_cpl.content_title_text == "Test Movie"

    def test_import_cpl_from_xml_file(self, test_dao, sample_tenant, tmp_path):
        """Test importing CPL from XML file."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        # Create sample CPL XML
        cpl_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<CompositionPlaylist xmlns="http://www.digicine.com/PROTO-ASDCP-CPL-20040511#">
    <Id>urn:uuid:550e8400-e29b-41d4-a716-446655440000</Id>
    <AnnotationText>Test CPL</AnnotationText>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
    <Issuer>Test Issuer</Issuer>
    <Creator>Test Creator</Creator>
    <ContentTitleText>Test Movie Title</ContentTitleText>
    <ContentKind>feature</ContentKind>
    <ReelList>
        <Reel>
            <Id>urn:uuid:reel-1</Id>
            <AssetList>
                <MainPicture>
                    <KeyId>urn:uuid:key-1</KeyId>
                </MainPicture>
                <MainSound>
                    <KeyId>urn:uuid:key-2</KeyId>
                </MainSound>
            </AssetList>
        </Reel>
    </ReelList>
</CompositionPlaylist>'''

        cpl_file = tmp_path / "test_cpl.xml"
        cpl_file.write_text(cpl_xml)

        # Import CPL
        cpl_id = test_dao.import_cpl_from_file(tenant_id, str(cpl_file))
        assert cpl_id > 0

        # Verify import
        cpl = test_dao.get_cpl_by_uuid("550e8400-e29b-41d4-a716-446655440000")
        assert cpl is not None
        assert cpl.content_title_text == "Test Movie Title"
        assert cpl.reel_count == 1


class TestDKDMOperations:
    """Test DKDM operations."""

    def test_create_dkdm(self, test_dao, sample_tenant):
        """Test creating a DKDM record."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        # Create CPL first
        cpl = CPLRecord(
            tenant_id=tenant_id,
            cpl_uuid="cpl-uuid-1",
            cpl_file_path="/path/to/cpl.xml",
            content_title_text="Test Movie",
            issue_date=datetime.now(timezone.utc)
        )
        cpl_id = test_dao.create_cpl(cpl)

        # Create DKDM
        dkdm = DKDMRecord(
            tenant_id=tenant_id,
            cpl_id=cpl_id,
            dkdm_uuid="dkdm-uuid-1",
            dkdm_file_path="/path/to/dkdm.xml",
            message_id="msg-1",
            content_title_text="Test Movie",
            composition_playlist_id="cpl-uuid-1",
            content_keys_not_valid_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
            content_keys_not_valid_after=datetime(2026, 1, 1, tzinfo=timezone.utc),
            issue_date=datetime.now(timezone.utc),
            signer_issuer_name="CN=Signer",
            signer_serial_number="12345",
            key_ids_json='[{"key_id": "key1", "key_type": "MDIK"}]'
        )

        dkdm_id = test_dao.create_dkdm(dkdm)
        assert dkdm_id > 0

    def test_import_dkdm_from_xml_file(self, test_dao, sample_tenant, tmp_path):
        """Test importing DKDM from XML file."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        # First create and import CPL
        cpl_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<CompositionPlaylist xmlns="http://www.digicine.com/PROTO-ASDCP-CPL-20040511#">
    <Id>urn:uuid:cpl-uuid-for-dkdm</Id>
    <ContentTitleText>Test Movie for DKDM</ContentTitleText>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
</CompositionPlaylist>'''

        cpl_file = tmp_path / "test_cpl_for_dkdm.xml"
        cpl_file.write_text(cpl_xml)
        test_dao.import_cpl_from_file(tenant_id, str(cpl_file))

        # Create DKDM XML
        dkdm_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-3/2006/ETM">
    <MessageId>urn:uuid:msg-1</MessageId>
    <AnnotationText>Test DKDM</AnnotationText>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
    <AuthenticatedPublic xmlns="http://www.smpte-ra.org/schemas/430-1/2006/KDM">
        <CompositionPlaylistId>urn:uuid:cpl-uuid-for-dkdm</CompositionPlaylistId>
        <ContentTitleText>Test Movie for DKDM</ContentTitleText>
        <ContentKeysNotValidBefore>2025-01-01T00:00:00Z</ContentKeysNotValidBefore>
        <ContentKeysNotValidAfter>2026-01-01T00:00:00Z</ContentKeysNotValidAfter>
        <KeyIdList>
            <TypedKeyId>
                <KeyType xmlns="http://www.smpte-ra.org/schemas/430-1/2006/KDM">MDIK</KeyType>
                <KeyId>urn:uuid:key-1</KeyId>
            </TypedKeyId>
        </KeyIdList>
    </AuthenticatedPublic>
</DCinemaSecurityMessage>'''

        dkdm_file = tmp_path / "test_dkdm.xml"
        dkdm_file.write_text(dkdm_xml)

        # Import DKDM
        dkdm_id = test_dao.import_dkdm_from_file(tenant_id, str(dkdm_file))
        assert dkdm_id > 0

    def test_import_dkdm_without_cpl_fails(self, test_dao, sample_tenant, tmp_path):
        """Test that importing DKDM without CPL fails."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        # Create DKDM XML with non-existent CPL UUID
        dkdm_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-3/2006/ETM">
    <MessageId>urn:uuid:msg-1</MessageId>
    <IssueDate>2025-01-01T00:00:00Z</IssueDate>
    <AuthenticatedPublic xmlns="http://www.smpte-ra.org/schemas/430-1/2006/KDM">
        <CompositionPlaylistId>urn:uuid:nonexistent-cpl</CompositionPlaylistId>
        <ContentTitleText>Test</ContentTitleText>
        <ContentKeysNotValidBefore>2025-01-01T00:00:00Z</ContentKeysNotValidBefore>
        <ContentKeysNotValidAfter>2026-01-01T00:00:00Z</ContentKeysNotValidAfter>
    </AuthenticatedPublic>
</DCinemaSecurityMessage>'''

        dkdm_file = tmp_path / "test_dkdm_no_cpl.xml"
        dkdm_file.write_text(dkdm_xml)

        # Should raise ValueError
        with pytest.raises(ValueError, match="CPL.*not found"):
            test_dao.import_dkdm_from_file(tenant_id, str(dkdm_file))


class TestKDMGeneratedOperations:
    """Test KDM generation record operations."""

    def test_create_kdm_generated(self, test_dao, sample_tenant):
        """Test creating a KDM generated record."""
        tenant_id = test_dao.create_tenant(sample_tenant)

        # Create CPL
        cpl = CPLRecord(
            tenant_id=tenant_id,
            cpl_uuid="cpl-uuid-1",
            cpl_file_path="/path/to/cpl.xml",
            content_title_text="Test Movie",
            issue_date=datetime.now(timezone.utc)
        )
        cpl_id = test_dao.create_cpl(cpl)

        # Create DKDM
        dkdm = DKDMRecord(
            tenant_id=tenant_id,
            cpl_id=cpl_id,
            dkdm_uuid="dkdm-uuid-1",
            dkdm_file_path="/path/to/dkdm.xml",
            message_id="msg-1",
            content_title_text="Test Movie",
            composition_playlist_id="cpl-uuid-1",
            content_keys_not_valid_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
            content_keys_not_valid_after=datetime(2026, 1, 1, tzinfo=timezone.utc),
            issue_date=datetime.now(timezone.utc),
            signer_issuer_name="CN=Signer",
            signer_serial_number="12345",
            key_ids_json='[]'
        )
        dkdm_id = test_dao.create_dkdm(dkdm)

        # Create certificate chain (simplified - just insert directly)
        with test_dao.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO certificate_chains (
                    tenant_id, chain_name, root_cert_path, signer_cert_path,
                    device_cert_path, root_thumbprint, signer_thumbprint,
                    device_thumbprint, chain_valid_from, chain_valid_until
                ) VALUES (?, 'TestChain', '/r', '/s', '/d', 't1', 't2', 't3',
                          '2025-01-01', '2026-01-01')
            ''', (tenant_id,))
            cert_chain_id = cursor.lastrowid
            conn.commit()

        # Create KDM generated record
        kdm = KDMGeneratedRecord(
            tenant_id=tenant_id,
            cpl_id=cpl_id,
            dkdm_id=dkdm_id,
            certificate_chain_id=cert_chain_id,
            kdm_uuid="kdm-uuid-1",
            kdm_file_path="/path/to/kdm.xml",
            message_id="kdm-msg-1",
            content_title_text="Test Movie",
            target_device_thumbprint="device-thumb",
            target_issuer_name="CN=Device",
            target_serial_number="54321",
            target_subject_name="CN=Projector",
            content_keys_not_valid_before=datetime(2025, 1, 1, tzinfo=timezone.utc),
            content_keys_not_valid_after=datetime(2026, 1, 1, tzinfo=timezone.utc),
            issue_date=datetime.now(timezone.utc)
        )

        kdm_id = test_dao.create_kdm_generated(kdm)
        assert kdm_id > 0


class TestStatistics:
    """Test database statistics functionality."""

    def test_get_statistics_empty_database(self, test_dao):
        """Test statistics on empty database."""
        stats = test_dao.get_statistics()

        assert stats['active_tenants'] == 0
        assert stats['total_tenants'] == 0
        assert stats['active_cpl'] == 0
        assert stats['active_dkdm'] == 0

    def test_get_statistics_with_data(self, test_dao, sample_tenant):
        """Test statistics with data."""
        # Create tenants
        test_dao.create_tenant(sample_tenant)
        tenant2 = TenantRecord(label="Cinema2", organization="Org2")
        test_dao.create_tenant(tenant2)

        stats = test_dao.get_statistics()

        assert stats['active_tenants'] == 2
        assert stats['total_tenants'] == 2

    def test_get_statistics_soft_deleted_records(self, test_dao, sample_tenant):
        """Test that statistics distinguish between active and total."""
        # Create tenants
        id1 = test_dao.create_tenant(sample_tenant)
        tenant2 = TenantRecord(label="Cinema2", organization="Org2")
        id2 = test_dao.create_tenant(tenant2)

        # Delete one
        test_dao.delete_tenant(id2)

        stats = test_dao.get_statistics()

        assert stats['active_tenants'] == 1
        assert stats['total_tenants'] == 2


class TestGetDAOFunction:
    """Test convenience function."""

    def test_get_dao_returns_instance(self):
        """Test that get_dao returns DAO instance."""
        dao = get_dao()
        assert isinstance(dao, KDMDataAccessObject)
