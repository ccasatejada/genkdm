"""
Data Access Object (DAO) layer for KDM management system.

Provides CRUD operations and business logic for all database entities:
- Tenants
- Self-signed certificates
- Certificate chains
- CPL (Composition Playlists)
- DKDM (Distribution Key Delivery Messages)
- Generated KDMs

All operations follow SMPTE standards and include validation.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from lxml import etree

from db.schema import KDMDatabase, get_database
from cryptography import x509
from cryptography.hazmat.backends import default_backend


@dataclass
class TenantRecord:
    """Tenant data record."""
    id: Optional[int] = None
    label: str = ""
    description: str = ""
    organization: str = ""
    contact_email: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True


@dataclass
class SelfSignedCertificateRecord:
    """Self-signed certificate data record."""
    id: Optional[int] = None
    certificate_name: str = ""
    certificate_path: str = ""
    private_key_path: str = ""
    certificate_pem: str = ""
    private_key_pem: str = ""
    subject_name: str = ""
    issuer_name: str = ""
    serial_number: str = ""
    thumbprint: str = ""
    not_valid_before: Optional[datetime] = None
    not_valid_after: Optional[datetime] = None
    is_smpte_compliant: bool = True
    certificate_role: str = ""
    key_usage: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True


@dataclass
class CertificateChainRecord:
    """Certificate chain data record."""
    id: Optional[int] = None
    tenant_id: int = 0
    chain_name: str = ""
    root_cert_path: str = ""
    signer_cert_path: str = ""
    device_cert_path: str = ""
    root_cert_pem: str = ""
    signer_cert_pem: str = ""
    device_cert_pem: str = ""
    root_key_path: str = ""
    signer_key_path: str = ""
    device_key_path: str = ""
    root_thumbprint: str = ""
    signer_thumbprint: str = ""
    device_thumbprint: str = ""
    chain_valid_from: Optional[datetime] = None
    chain_valid_until: Optional[datetime] = None
    is_smpte_compliant: bool = True
    smpte_role: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True


@dataclass
class CPLRecord:
    """CPL (Composition Playlist) data record."""
    id: Optional[int] = None
    tenant_id: int = 0
    cpl_uuid: str = ""
    cpl_file_path: str = ""
    annotation_text: str = ""
    content_title_text: str = ""
    content_kind: str = ""
    content_version_id: str = ""
    content_version_label: str = ""
    issue_date: Optional[datetime] = None
    issuer: str = ""
    creator: str = ""
    total_duration: int = 0
    edit_rate_numerator: int = 24
    edit_rate_denominator: int = 1
    reel_count: int = 0
    key_ids_json: str = "[]"
    screen_aspect_ratio: str = ""
    language_codes: str = "[]"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True


@dataclass
class DKDMRecord:
    """DKDM (Distribution KDM) data record."""
    id: Optional[int] = None
    tenant_id: int = 0
    cpl_id: int = 0
    dkdm_uuid: str = ""
    dkdm_file_path: str = ""
    message_id: str = ""
    annotation_text: str = ""
    content_title_text: str = ""
    composition_playlist_id: str = ""
    content_keys_not_valid_before: Optional[datetime] = None
    content_keys_not_valid_after: Optional[datetime] = None
    issue_date: Optional[datetime] = None
    signer_issuer_name: str = ""
    signer_serial_number: str = ""
    recipient_issuer_name: str = ""
    recipient_serial_number: str = ""
    recipient_subject_name: str = ""
    device_list_identifier: str = ""
    device_thumbprints_json: str = "[]"
    key_ids_json: str = "[]"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True


@dataclass
class KDMGeneratedRecord:
    """Generated KDM data record."""
    id: Optional[int] = None
    tenant_id: int = 0
    cpl_id: int = 0
    dkdm_id: int = 0
    certificate_chain_id: int = 0
    kdm_uuid: str = ""
    kdm_file_path: str = ""
    signed_kdm_file_path: str = ""
    message_id: str = ""
    annotation_text: str = ""
    content_title_text: str = ""
    target_device_thumbprint: str = ""
    target_issuer_name: str = ""
    target_serial_number: str = ""
    target_subject_name: str = ""
    content_keys_not_valid_before: Optional[datetime] = None
    content_keys_not_valid_after: Optional[datetime] = None
    issue_date: Optional[datetime] = None
    signer_certificate_id: Optional[int] = None
    is_signed: bool = False
    signature_algorithm: str = ""
    generation_timestamp: Optional[datetime] = None
    generator_version: str = ""
    generation_parameters_json: str = "{}"
    is_valid: bool = True
    validation_errors_json: str = "[]"
    last_validated_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True


class KDMDataAccessObject:
    """Main DAO class for KDM system database operations."""

    def __init__(self, database: Optional[KDMDatabase] = None):
        """Initialize DAO with database connection."""
        self.db = database or get_database()

    # TENANT OPERATIONS
    def create_tenant(self, tenant: TenantRecord) -> int:
        """Create a new tenant."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO tenants (label, description, organization, contact_email)
                VALUES (?, ?, ?, ?)
            ''', (tenant.label, tenant.description, tenant.organization, tenant.contact_email))

            tenant_id = cursor.lastrowid
            conn.commit()
            print(f"✅ Created tenant: {tenant.label} (ID: {tenant_id})")
            return tenant_id

    def get_tenant(self, tenant_id: int) -> Optional[TenantRecord]:
        """Get tenant by ID."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tenants WHERE id = ? AND is_active = 1', (tenant_id,))
            row = cursor.fetchone()

            if row:
                return TenantRecord(**dict(row))
            return None

    def get_tenant_by_label(self, label: str) -> Optional[TenantRecord]:
        """Get tenant by label."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tenants WHERE label = ? AND is_active = 1', (label,))
            row = cursor.fetchone()

            if row:
                return TenantRecord(**dict(row))
            return None

    def list_tenants(self, active_only: bool = True) -> List[TenantRecord]:
        """List all tenants."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            where_clause = 'WHERE is_active = 1' if active_only else ''
            cursor.execute(f'SELECT * FROM tenants {where_clause} ORDER BY label')
            rows = cursor.fetchall()

            return [TenantRecord(**dict(row)) for row in rows]

    def update_tenant(self, tenant: TenantRecord) -> bool:
        """Update existing tenant."""
        if not tenant.id:
            return False

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE tenants
                SET label = ?, description = ?, organization = ?, contact_email = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (tenant.label, tenant.description, tenant.organization,
                  tenant.contact_email, tenant.id))

            conn.commit()
            return cursor.rowcount > 0

    def delete_tenant(self, tenant_id: int) -> bool:
        """Soft delete tenant."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE tenants SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (tenant_id,))

            conn.commit()
            return cursor.rowcount > 0

    # SELF-SIGNED CERTIFICATE OPERATIONS
    def create_self_signed_certificate(self, cert: SelfSignedCertificateRecord) -> int:
        """Create a new self-signed certificate record."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO self_signed_certificates (
                    certificate_name, certificate_path, private_key_path,
                    certificate_pem, private_key_pem, subject_name, issuer_name,
                    serial_number, thumbprint, not_valid_before, not_valid_after,
                    is_smpte_compliant, certificate_role, key_usage
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cert.certificate_name, cert.certificate_path, cert.private_key_path,
                cert.certificate_pem, cert.private_key_pem, cert.subject_name,
                cert.issuer_name, cert.serial_number, cert.thumbprint,
                cert.not_valid_before, cert.not_valid_after, cert.is_smpte_compliant,
                cert.certificate_role, cert.key_usage
            ))

            cert_id = cursor.lastrowid
            conn.commit()
            print(f"✅ Created self-signed certificate: {cert.certificate_name} (ID: {cert_id})")
            return cert_id

    def import_certificate_from_file(self, cert_path: str, key_path: str, name: str) -> int:
        """Import certificate from PEM files and extract metadata."""
        # Read certificate file
        with open(cert_path, 'rb') as f:
            cert_pem = f.read().decode('utf-8')

        # Read private key file
        with open(key_path, 'rb') as f:
            key_pem = f.read().decode('utf-8')

        # Parse certificate to extract metadata
        cert_data = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Extract certificate information
        subject_name = cert_data.subject.rfc4514_string()
        issuer_name = cert_data.issuer.rfc4514_string()
        serial_number = str(cert_data.serial_number)

        # Calculate thumbprint (SHA-1 hash of DER, base64 encoded)
        import hashlib
        import base64
        from cryptography.hazmat.primitives.serialization import Encoding
        der_bytes = cert_data.public_bytes(encoding=Encoding.DER)
        thumbprint = base64.b64encode(hashlib.sha1(der_bytes).digest()).decode()

        # Create certificate record
        cert_record = SelfSignedCertificateRecord(
            certificate_name=name,
            certificate_path=cert_path,
            private_key_path=key_path,
            certificate_pem=cert_pem,
            private_key_pem=key_pem,
            subject_name=subject_name,
            issuer_name=issuer_name,
            serial_number=serial_number,
            thumbprint=thumbprint,
            not_valid_before=cert_data.not_valid_before,
            not_valid_after=cert_data.not_valid_after,
            certificate_role="ROOT" if subject_name == issuer_name else "LEAF"
        )

        return self.create_self_signed_certificate(cert_record)

    # CPL OPERATIONS
    def import_cpl_from_file(self, tenant_id: int, cpl_file_path: str) -> int:
        """Import CPL from XML file and extract metadata."""
        # Parse CPL XML
        with open(cpl_file_path, 'rb') as f:
            xml_doc = etree.parse(f)
            root = xml_doc.getroot()

        # Define namespaces
        ns = {'cpl': 'http://www.digicine.com/PROTO-ASDCP-CPL-20040511#'}

        # Extract CPL metadata
        cpl_uuid = root.findtext('.//cpl:Id', '', ns).replace('urn:uuid:', '')
        annotation_text = root.findtext('.//cpl:AnnotationText', '', ns)
        content_title = root.findtext('.//cpl:ContentTitleText', '', ns)
        content_kind = root.findtext('.//cpl:ContentKind', '', ns)

        # Issue information
        issue_date_str = root.findtext('.//cpl:IssueDate', '', ns)
        issue_date = datetime.fromisoformat(issue_date_str.replace('Z', '+00:00')) if issue_date_str else datetime.now(timezone.utc)

        issuer = root.findtext('.//cpl:Issuer', '', ns)
        creator = root.findtext('.//cpl:Creator', '', ns)

        # Extract key IDs from reels
        key_ids = []
        reel_count = 0

        for reel in root.findall('.//cpl:Reel', ns):
            reel_count += 1
            reel_id = reel.findtext('.//cpl:Id', '', ns).replace('urn:uuid:', '')

            # Main picture keys
            for picture in reel.findall('.//cpl:MainPicture', ns):
                key_id = picture.findtext('.//cpl:KeyId', '', ns).replace('urn:uuid:', '')
                if key_id:
                    key_ids.append({"key_id": key_id, "key_type": "MDIK", "reel_id": reel_id})

            # Main sound keys
            for sound in reel.findall('.//cpl:MainSound', ns):
                key_id = sound.findtext('.//cpl:KeyId', '', ns).replace('urn:uuid:', '')
                if key_id:
                    key_ids.append({"key_id": key_id, "key_type": "MDAK", "reel_id": reel_id})

        # Create CPL record
        cpl_record = CPLRecord(
            tenant_id=tenant_id,
            cpl_uuid=cpl_uuid,
            cpl_file_path=cpl_file_path,
            annotation_text=annotation_text,
            content_title_text=content_title,
            content_kind=content_kind,
            issue_date=issue_date,
            issuer=issuer,
            creator=creator,
            reel_count=reel_count,
            key_ids_json=json.dumps(key_ids)
        )

        return self.create_cpl(cpl_record)

    def create_cpl(self, cpl: CPLRecord) -> int:
        """Create a new CPL record."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO cpl (
                    tenant_id, cpl_uuid, cpl_file_path, annotation_text,
                    content_title_text, content_kind, content_version_id,
                    content_version_label, issue_date, issuer, creator,
                    total_duration, edit_rate_numerator, edit_rate_denominator,
                    reel_count, key_ids_json, screen_aspect_ratio, language_codes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cpl.tenant_id, cpl.cpl_uuid, cpl.cpl_file_path, cpl.annotation_text,
                cpl.content_title_text, cpl.content_kind, cpl.content_version_id,
                cpl.content_version_label, cpl.issue_date, cpl.issuer, cpl.creator,
                cpl.total_duration, cpl.edit_rate_numerator, cpl.edit_rate_denominator,
                cpl.reel_count, cpl.key_ids_json, cpl.screen_aspect_ratio, cpl.language_codes
            ))

            cpl_id = cursor.lastrowid
            conn.commit()
            print(f"✅ Created CPL: {cpl.content_title_text} (ID: {cpl_id})")
            return cpl_id

    # DKDM OPERATIONS
    def import_dkdm_from_file(self, tenant_id: int, dkdm_file_path: str) -> int:
        """Import DKDM from XML file and extract metadata."""
        # Parse DKDM XML
        with open(dkdm_file_path, 'rb') as f:
            xml_doc = etree.parse(f)
            root = xml_doc.getroot()

        # Define namespaces
        etm_ns = 'http://www.smpte-ra.org/schemas/430-3/2006/ETM'
        kdm_ns = 'http://www.smpte-ra.org/schemas/430-1/2006/KDM'

        # Extract DKDM metadata
        message_id = root.findtext(f'.//{{{etm_ns}}}MessageId', '')
        annotation_text = root.findtext(f'.//{{{etm_ns}}}AnnotationText', '')

        # Issue date
        issue_date_str = root.findtext(f'.//{{{etm_ns}}}IssueDate', '')
        issue_date = datetime.fromisoformat(issue_date_str.replace('Z', '+00:00')) if issue_date_str else datetime.now(timezone.utc)

        # KDM-specific information
        cpl_id = root.findtext(f'.//{{{kdm_ns}}}CompositionPlaylistId', '').replace('urn:uuid:', '')
        content_title = root.findtext(f'.//{{{kdm_ns}}}ContentTitleText', '')

        # Validity period
        not_before_str = root.findtext(f'.//{{{kdm_ns}}}ContentKeysNotValidBefore', '')
        not_after_str = root.findtext(f'.//{{{kdm_ns}}}ContentKeysNotValidAfter', '')

        not_before = datetime.fromisoformat(not_before_str.replace('Z', '+00:00')) if not_before_str else datetime.now(timezone.utc)
        not_after = datetime.fromisoformat(not_after_str.replace('Z', '+00:00')) if not_after_str else datetime.now(timezone.utc)

        # Extract key IDs
        key_ids = []
        for typed_key in root.findall(f'.//{{{kdm_ns}}}TypedKeyId'):
            key_type = typed_key.findtext(f'.//{{{kdm_ns}}}KeyType', '')
            key_id = typed_key.findtext(f'.//{{{kdm_ns}}}KeyId', '').replace('urn:uuid:', '')
            if key_id:
                key_ids.append({"key_id": key_id, "key_type": key_type})

        # Find corresponding CPL
        cpl_record = self.get_cpl_by_uuid(cpl_id)
        if not cpl_record:
            raise ValueError(f"CPL with UUID {cpl_id} not found. Import CPL first.")

        # Create DKDM record
        dkdm_uuid = str(uuid.uuid4())
        dkdm_record = DKDMRecord(
            tenant_id=tenant_id,
            cpl_id=cpl_record.id,
            dkdm_uuid=dkdm_uuid,
            dkdm_file_path=dkdm_file_path,
            message_id=message_id,
            annotation_text=annotation_text,
            content_title_text=content_title,
            composition_playlist_id=cpl_id,
            content_keys_not_valid_before=not_before,
            content_keys_not_valid_after=not_after,
            issue_date=issue_date,
            key_ids_json=json.dumps(key_ids)
        )

        return self.create_dkdm(dkdm_record)

    def create_dkdm(self, dkdm: DKDMRecord) -> int:
        """Create a new DKDM record."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO dkdm (
                    tenant_id, cpl_id, dkdm_uuid, dkdm_file_path, message_id,
                    annotation_text, content_title_text, composition_playlist_id,
                    content_keys_not_valid_before, content_keys_not_valid_after,
                    issue_date, signer_issuer_name, signer_serial_number,
                    recipient_issuer_name, recipient_serial_number, recipient_subject_name,
                    device_list_identifier, device_thumbprints_json, key_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                dkdm.tenant_id, dkdm.cpl_id, dkdm.dkdm_uuid, dkdm.dkdm_file_path,
                dkdm.message_id, dkdm.annotation_text, dkdm.content_title_text,
                dkdm.composition_playlist_id, dkdm.content_keys_not_valid_before,
                dkdm.content_keys_not_valid_after, dkdm.issue_date, dkdm.signer_issuer_name,
                dkdm.signer_serial_number, dkdm.recipient_issuer_name, dkdm.recipient_serial_number,
                dkdm.recipient_subject_name, dkdm.device_list_identifier,
                dkdm.device_thumbprints_json, dkdm.key_ids_json
            ))

            dkdm_id = cursor.lastrowid
            conn.commit()
            print(f"✅ Created DKDM: {dkdm.content_title_text} (ID: {dkdm_id})")
            return dkdm_id

    def get_cpl_by_uuid(self, cpl_uuid: str) -> Optional[CPLRecord]:
        """Get CPL by UUID."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM cpl WHERE cpl_uuid = ? AND is_active = 1', (cpl_uuid,))
            row = cursor.fetchone()

            if row:
                return CPLRecord(**dict(row))
            return None

    # KDM GENERATED OPERATIONS
    def create_kdm_generated(self, kdm: KDMGeneratedRecord) -> int:
        """Create a new generated KDM record."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO kdm_generated (
                    tenant_id, cpl_id, dkdm_id, certificate_chain_id, kdm_uuid,
                    kdm_file_path, signed_kdm_file_path, message_id, annotation_text,
                    content_title_text, target_device_thumbprint, target_issuer_name,
                    target_serial_number, target_subject_name, content_keys_not_valid_before,
                    content_keys_not_valid_after, issue_date, signer_certificate_id,
                    is_signed, signature_algorithm, generation_timestamp, generator_version,
                    generation_parameters_json, is_valid, validation_errors_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                kdm.tenant_id, kdm.cpl_id, kdm.dkdm_id, kdm.certificate_chain_id,
                kdm.kdm_uuid, kdm.kdm_file_path, kdm.signed_kdm_file_path, kdm.message_id,
                kdm.annotation_text, kdm.content_title_text, kdm.target_device_thumbprint,
                kdm.target_issuer_name, kdm.target_serial_number, kdm.target_subject_name,
                kdm.content_keys_not_valid_before, kdm.content_keys_not_valid_after,
                kdm.issue_date, kdm.signer_certificate_id, kdm.is_signed, kdm.signature_algorithm,
                kdm.generation_timestamp, kdm.generator_version, kdm.generation_parameters_json,
                kdm.is_valid, kdm.validation_errors_json
            ))

            kdm_id = cursor.lastrowid
            conn.commit()
            print(f"✅ Created generated KDM: {kdm.content_title_text} (ID: {kdm_id})")
            return kdm_id

    # UTILITY OPERATIONS
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            stats = {}
            tables = ['tenants', 'self_signed_certificates', 'certificate_chains',
                     'cpl', 'dkdm', 'kdm_generated']

            for table in tables:
                cursor.execute(f'SELECT COUNT(*) FROM {table} WHERE is_active = 1')
                stats[f'active_{table}'] = cursor.fetchone()[0]

                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[f'total_{table}'] = cursor.fetchone()[0]

            return stats


# Convenience function
def get_dao() -> KDMDataAccessObject:
    """Get DAO instance with default configuration."""
    return KDMDataAccessObject()


if __name__ == "__main__":
    # Example usage
    print("KDM Data Access Object")
    print("=" * 50)

    dao = get_dao()

    # Show statistics
    stats = dao.get_statistics()
    print("Database Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")