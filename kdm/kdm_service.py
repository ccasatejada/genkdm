"""
KDM Generation Service - Complete workflow for generating KDMs from DKDMs.

This service orchestrates the entire KDM generation process:
1. Tenant authorization (verify ownership of DKDM, CPL, certificates)
2. DKDM decryption with service provider's self-signed certificate
3. Multi-device KDM generation (re-encrypt for target projectors)
4. KDM signing with SMPTE compliance
5. File management and database tracking
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from lxml import etree

from db.dao import get_dao, KDMDataAccessObject, KDMGeneratedRecord
from exceptions.exceptions import KDMGenerationError
from kdm.internal.kdm_validator import validate_kdm_xml, check_kdm_against_cpl
from utils.logger import get_logger
from utils.utils import get_current_path

log = get_logger()


class KDMGenerationService:
    """Service for generating KDMs from DKDMs with full workflow support."""

    def __init__(self, dao: Optional[KDMDataAccessObject] = None):
        """
        Initialize KDM generation service.

        Args:
            dao: Data access object (defaults to get_dao())
        """
        self.dao = dao or get_dao()
        self.output_dir = Path(f"{get_current_path()}/files/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_kdm(
        self,
        tenant_id: int,
        dkdm_id: int,
        certificate_chain_ids: List[int],
        start_datetime: datetime,
        end_datetime: datetime,
        self_signed_cert_path: str,
        self_signed_key_path: str,
        annotation: Optional[str] = None,
        timezone_name: Optional[str] = None,
        sign: bool = True
    ) -> List[int]:
        """
        Generate KDMs for multiple target devices from a single DKDM.

        Args:
            tenant_id: Tenant making the request
            dkdm_id: DKDM ID to use as source
            certificate_chain_ids: List of target certificate chain IDs
            start_datetime: KDM validity start
            end_datetime: KDM validity end
            self_signed_cert_path: Path to service provider's device certificate
            self_signed_key_path: Path to service provider's private key
            annotation: Custom annotation text (optional)
            timezone_name: Target timezone (optional)
            sign: Whether to sign the KDM (default True)

        Returns:
            List of generated KDM IDs

        Raises:
            KDMGenerationError: If generation fails at any step
        """
        log.info(f"Starting KDM generation for tenant {tenant_id}, DKDM {dkdm_id}")

        # Step 1: Authorization - Verify tenant owns DKDM
        if not self.dao.verify_tenant_owns_dkdm(tenant_id, dkdm_id):
            raise KDMGenerationError(f"Tenant {tenant_id} does not own DKDM {dkdm_id}")

        # Step 2: Fetch DKDM from database
        dkdm = self.dao.get_dkdm_by_id(dkdm_id)
        if not dkdm:
            raise KDMGenerationError(f"DKDM {dkdm_id} not found")

        log.info(f"DKDM authorized: {dkdm.content_title_text}")

        # Step 3: Verify CPL exists and belongs to tenant
        cpl = self.dao.get_cpl_by_uuid(dkdm.composition_playlist_id)
        if not cpl:
            raise KDMGenerationError(f"CPL {dkdm.composition_playlist_id} not found")

        if not self.dao.verify_tenant_owns_cpl(tenant_id, cpl.id):
            raise KDMGenerationError(f"Tenant {tenant_id} does not own CPL {cpl.id}")

        log.info(f"CPL authorized: {cpl.content_title_text}")

        # Step 4: Load DKDM file and extract encrypted content keys
        dkdm_file_path = Path(dkdm.dkdm_file_path)
        if not dkdm_file_path.exists():
            raise KDMGenerationError(f"DKDM file not found: {dkdm_file_path}")

        encrypted_keys = self._extract_encrypted_keys_from_dkdm(str(dkdm_file_path))
        log.info(f"Extracted {len(encrypted_keys)} encrypted key(s) from DKDM")

        # Step 5: Decrypt content keys with service provider's self-signed key
        content_keys = self._decrypt_content_keys(
            encrypted_keys,
            self_signed_key_path
        )
        log.info(f"Decrypted content keys with self-signed certificate")

        # Step 6: Generate KDMs for all certificate chains (global, shared by all tenants)
        generated_kdm_ids = []

        for chain_id in certificate_chain_ids:
            # Step 7: Generate KDM for this certificate chain
            try:
                kdm_id = self._generate_kdm_for_target(
                    tenant_id=tenant_id,
                    dkdm=dkdm,
                    cpl=cpl,
                    chain_id=chain_id,
                    content_keys=content_keys,
                    start_datetime=start_datetime,
                    end_datetime=end_datetime,
                    self_signed_cert_path=self_signed_cert_path,
                    self_signed_key_path=self_signed_key_path,
                    annotation=annotation,
                    timezone_name=timezone_name,
                    sign=sign
                )
                generated_kdm_ids.append(kdm_id)
                log.info(f"Generated KDM {kdm_id} for certificate chain {chain_id}")

            except Exception as e:
                log.error(f"Failed to generate KDM for chain {chain_id}: {e}")
                # Continue with other chains

        if not generated_kdm_ids:
            raise KDMGenerationError("No KDMs were generated successfully")

        log.info(f"Successfully generated {len(generated_kdm_ids)} KDM(s)")
        return generated_kdm_ids

    def _extract_encrypted_keys_from_dkdm(self, dkdm_path: str) -> List[dict]:
        """Extract encrypted content keys from DKDM XML."""
        with open(dkdm_path, 'rb') as f:
            tree = etree.parse(f)
            root = tree.getroot()

        encrypted_keys = []

        # Find all EncryptedKey elements
        for encrypted_key_elem in root.findall('.//{*}EncryptedKey'):
            # Get key ID from corresponding TypedKeyId
            key_id_elem = encrypted_key_elem.find('.//{*}KeyId')
            key_type_elem = encrypted_key_elem.find('.//{*}KeyType')
            cipher_value_elem = encrypted_key_elem.find('.//{*}CipherValue')

            if cipher_value_elem is not None and cipher_value_elem.text:
                encrypted_keys.append({
                    'key_id': key_id_elem.text.strip() if key_id_elem is not None else '',
                    'key_type': key_type_elem.text.strip() if key_type_elem is not None else 'MDIK',
                    'cipher_value': cipher_value_elem.text.strip()
                })

        # If no EncryptedKey found, try extracting from AuthenticatedPrivate
        if not encrypted_keys:
            cipher_value = root.findtext(".//{*}CipherValue", '').strip()
            if cipher_value:
                # Get key IDs from KDMRequiredExtensions
                key_id = root.findtext(".//{*}KeyId", '').strip()
                encrypted_keys.append({
                    'key_id': key_id,
                    'key_type': 'MDIK',
                    'cipher_value': cipher_value
                })

        return encrypted_keys

    def _decrypt_content_keys(self, encrypted_keys: List[dict], private_key_path: str) -> List[dict]:
        """Decrypt content keys using service provider's private key."""
        import base64

        # Load private key
        with open(private_key_path, 'rb') as f:
            private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

        decrypted_keys = []

        for enc_key in encrypted_keys:
            try:
                encrypted_data = base64.b64decode(enc_key['cipher_value'])

                # Decrypt using RSA-OAEP with SHA-1 (SMPTE standard)
                decrypted = private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )

                decrypted_keys.append({
                    'key_id': enc_key['key_id'],
                    'key_type': enc_key['key_type'],
                    'decrypted_key': decrypted
                })

            except Exception as e:
                log.error(f"Failed to decrypt key {enc_key.get('key_id', 'unknown')}: {e}")
                raise KDMGenerationError(f"Content key decryption failed: {e}")

        return decrypted_keys

    def _generate_kdm_for_target(
        self,
        tenant_id: int,
        dkdm,
        cpl,
        chain_id: int,
        content_keys: List[dict],
        start_datetime: datetime,
        end_datetime: datetime,
        self_signed_cert_path: str,
        self_signed_key_path: str,
        annotation: Optional[str],
        timezone_name: Optional[str],
        sign: bool
    ) -> int:
        """Generate a single KDM for a target certificate chain."""
        import base64
        from kdm.internal.sign_smpte_kdm import sign_smpte_kdm

        # Fetch certificate chain
        chain = self.dao.get_certificate_chain(chain_id)
        if not chain:
            raise KDMGenerationError(f"Certificate chain {chain_id} not found")

        # Load target device certificate
        device_cert = x509.load_pem_x509_certificate(
            chain.device_cert_pem.encode(),
            default_backend()
        )

        # Encrypt content keys for target device
        encrypted_keys_for_target = []
        target_public_key = device_cert.public_key()

        for key_data in content_keys:
            encrypted = target_public_key.encrypt(
                key_data['decrypted_key'],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
            encrypted_keys_for_target.append({
                'key_id': key_data['key_id'],
                'key_type': key_data['key_type'],
                'encrypted_key': base64.b64encode(encrypted).decode()
            })

        # Build KDM XML
        kdm_xml = self._build_kdm_xml(
            device_cert=device_cert,
            encrypted_keys=encrypted_keys_for_target,
            cpl_id=cpl.cpl_uuid,
            content_title=annotation or dkdm.content_title_text,
            start_datetime=start_datetime,
            end_datetime=end_datetime,
            device_thumbprint=chain.device_thumbprint
        )

        # Save unsigned KDM
        kdm_uuid = str(uuid.uuid4())
        kdm_filename = f"KDM_{chain.chain_name.replace(' ', '_')}_{kdm_uuid[:8]}.xml"
        kdm_path = self.output_dir / kdm_filename

        with open(kdm_path, 'w', encoding='utf-8') as f:
            f.write(kdm_xml)

        log.info(f"Saved unsigned KDM: {kdm_path}")

        # Validate KDM against XSD schema
        xsd_path = Path(f"{get_current_path()}/files/xsd/DCinemaSecurityMessage.xsd")
        if xsd_path.exists():
            try:
                if validate_kdm_xml(str(kdm_path), str(xsd_path)):
                    log.info("KDM XSD validation passed")
                else:
                    log.warning("KDM XSD validation failed")
            except Exception as e:
                log.warning(f"KDM XSD validation error: {e}")
        else:
            log.debug(f"XSD schema not found at {xsd_path}, skipping validation")

        # Check KDM against CPL
        cpl_path = Path(cpl.cpl_file_path)
        if cpl_path.exists():
            try:
                if check_kdm_against_cpl(str(kdm_path), str(cpl_path)):
                    log.info("KDM-CPL cross-check passed")
                else:
                    log.warning("KDM-CPL cross-check failed")
            except Exception as e:
                log.warning(f"KDM-CPL cross-check error: {e}")

        # Sign KDM if requested (SMPTE ST 430-3)
        signed_kdm_path = None
        if sign:
            try:
                # sign_smpte_kdm(kdm_path, output_path, key_path, cert_path)
                signed_kdm_path = sign_smpte_kdm(
                    kdm_file_path=str(kdm_path),
                    signer_key_path=self_signed_key_path,
                    signer_cert_path=self_signed_cert_path
                )
                log.info(f"Signed KDM: {signed_kdm_path}")

                # Validate signed KDM against XSD
                if xsd_path.exists():
                    try:
                        if validate_kdm_xml(str(signed_kdm_path), str(xsd_path)):
                            log.info("Signed KDM XSD validation passed")
                        else:
                            log.warning("Signed KDM XSD validation failed")
                    except Exception as e:
                        log.warning(f"Signed KDM XSD validation error: {e}")
            except Exception as e:
                log.warning(f"KDM signing failed: {e}")

        # Create database record
        kdm_record = KDMGeneratedRecord(
            tenant_id=tenant_id,
            cpl_id=cpl.id,
            dkdm_id=dkdm.id,
            certificate_chain_id=chain_id,
            kdm_uuid=kdm_uuid,
            kdm_file_path=str(kdm_path),
            signed_kdm_file_path=signed_kdm_path,
            message_id=f"urn:uuid:{kdm_uuid}",
            annotation_text=annotation or dkdm.annotation_text,
            content_title_text=dkdm.content_title_text,
            target_device_thumbprint=chain.device_thumbprint,
            target_issuer_name=device_cert.issuer.rfc4514_string(),
            target_serial_number=str(device_cert.serial_number),
            target_subject_name=device_cert.subject.rfc4514_string(),
            content_keys_not_valid_before=start_datetime,
            content_keys_not_valid_after=end_datetime,
            issue_date=datetime.now(timezone.utc),
            is_signed=signed_kdm_path is not None,
            signature_algorithm="RSA-SHA256" if signed_kdm_path else None,
            generation_timestamp=datetime.now(timezone.utc),
            generator_version="genkdm-1.0",
            generation_parameters_json=json.dumps({
                "timezone": timezone_name,
                "annotation": annotation
            })
        )

        return self.dao.create_kdm_generated(kdm_record)

    def _build_kdm_xml(
        self,
        device_cert: x509.Certificate,
        encrypted_keys: List[dict],
        cpl_id: str,
        content_title: str,
        start_datetime: datetime,
        end_datetime: datetime,
        device_thumbprint: str
    ) -> str:
        """Build KDM XML according to SMPTE standards."""
        message_id = str(uuid.uuid4())
        issue_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        valid_from = start_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
        valid_until = end_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build key list
        key_list_xml = ""
        for key in encrypted_keys:
            key_id = key['key_id']
            if not key_id.startswith('urn:uuid:'):
                key_id = f"urn:uuid:{key_id}"

            key_list_xml += f"""
          <TypedKeyId>
            <KeyType scope="http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type">{key['key_type']}</KeyType>
            <KeyId>{key_id}</KeyId>
          </TypedKeyId>"""

        # Build encrypted key list
        encrypted_key_xml = ""
        for key in encrypted_keys:
            encrypted_key_xml += f"""
  <AuthenticatedPrivate>
    <EncryptedKey Id="ID_EncryptedKey">
      <enc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
      <dsig:KeyInfo>
        <dsig:X509Data>
          <dsig:X509IssuerSerial>
            <dsig:X509IssuerName>{device_cert.issuer.rfc4514_string()}</dsig:X509IssuerName>
            <dsig:X509SerialNumber>{device_cert.serial_number}</dsig:X509SerialNumber>
          </dsig:X509IssuerSerial>
        </dsig:X509Data>
      </dsig:KeyInfo>
      <enc:CipherData>
        <enc:CipherValue>{key['encrypted_key']}</enc:CipherValue>
      </enc:CipherData>
    </EncryptedKey>
  </AuthenticatedPrivate>"""

        if not cpl_id.startswith('urn:uuid:'):
            cpl_id = f"urn:uuid:{cpl_id}"

        kdm_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-3/2006/ETM" xmlns:kdm="http://www.smpte-ra.org/schemas/430-1/2006/KDM" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" xmlns:enc="http://www.w3.org/2001/04/xmlenc#">
  <AuthenticatedPublic Id="ID_AuthenticatedPublic">
    <MessageId>urn:uuid:{message_id}</MessageId>
    <MessageType>http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type</MessageType>
    <AnnotationText>{content_title} KDM</AnnotationText>
    <IssueDate>{issue_date}</IssueDate>
    <Signer>
      <dsig:X509IssuerName>{device_cert.issuer.rfc4514_string()}</dsig:X509IssuerName>
      <dsig:X509SerialNumber>{device_cert.serial_number}</dsig:X509SerialNumber>
    </Signer>
    <RequiredExtensions>
      <KDMRequiredExtensions xmlns="http://www.smpte-ra.org/schemas/430-1/2006/KDM">
        <Recipient>
          <X509IssuerSerial>
            <dsig:X509IssuerName>{device_cert.issuer.rfc4514_string()}</dsig:X509IssuerName>
            <dsig:X509SerialNumber>{device_cert.serial_number}</dsig:X509SerialNumber>
          </X509IssuerSerial>
          <X509SubjectName>{device_cert.subject.rfc4514_string()}</X509SubjectName>
        </Recipient>
        <CompositionPlaylistId>{cpl_id}</CompositionPlaylistId>
        <ContentTitleText>{content_title}</ContentTitleText>
        <ContentKeysNotValidBefore>{valid_from}</ContentKeysNotValidBefore>
        <ContentKeysNotValidAfter>{valid_until}</ContentKeysNotValidAfter>
        <AuthorizedDeviceInfo>
          <DeviceListIdentifier>urn:uuid:{str(uuid.uuid4())}</DeviceListIdentifier>
          <DeviceListDescription>Authorized devices for {content_title}</DeviceListDescription>
          <DeviceList>
            <CertificateThumbprint>{device_thumbprint}</CertificateThumbprint>
          </DeviceList>
        </AuthorizedDeviceInfo>
        <KeyIdList>{key_list_xml}
        </KeyIdList>
      </KDMRequiredExtensions>
    </RequiredExtensions>
  </AuthenticatedPublic>{encrypted_key_xml}
</DCinemaSecurityMessage>"""

        return kdm_xml


# Convenience function
def get_kdm_service() -> KDMGenerationService:
    """Get KDM generation service instance."""
    return KDMGenerationService()