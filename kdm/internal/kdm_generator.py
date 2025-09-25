import base64
import uuid
from datetime import timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from lxml import etree

from utils.utils import get_current_path


class KDMGenerator:
    def __init__(self, server_private_key_path, server_cert_path):
        self.server_private_key_path = Path(server_private_key_path)
        self.server_cert_path = Path(server_cert_path)
        self.output_dir = Path(f"{get_current_path()}/files/output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def extract_dkdm_info(self, dkdm_path):
        with open(dkdm_path, "rb") as f:
            tree = etree.parse(f)
            root = tree.getroot()
            encrypted_cek_b64 = root.findtext(".//{*}CipherValue")
            key_id = root.findtext(".//{*}KeyId").strip()
            cpl_id = root.findtext(".//{*}CompositionPlaylistId").strip()

        encrypted_cek = base64.b64decode(encrypted_cek_b64)
        return encrypted_cek, key_id, cpl_id

    def decrypt_content_key(self, encrypted_cek):
        with open(self.server_private_key_path, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

        content_key = private_key.decrypt(
            encrypted_cek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return content_key

    @staticmethod
    def load_target_certificate(target_cert_path):
        with open(target_cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), backend=default_backend())

    @staticmethod
    def encrypt_key_for_target(content_key, target_cert):
        target_public_key = target_cert.public_key()
        encrypted_key = target_public_key.encrypt(
            content_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return base64.b64encode(encrypted_key).decode()

    @staticmethod
    def format_datetime_utc(dt, tz):
        if tz:
            dt = dt.replace(tzinfo=tz).astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def build_kdm_xml(self, content_key, key_id, cpl_id, target_cert,
                      start_datetime, end_datetime, content_title, target_timezone=None):

        valid_from = self.format_datetime_utc(start_datetime, target_timezone)
        valid_until = self.format_datetime_utc(end_datetime, target_timezone)

        encrypted_key_b64 = self.encrypt_key_for_target(content_key, target_cert)

        kdm_xml = (
            f"""<?xml version="1.0" encoding="UTF-8"?>
                <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                  <AuthenticatedPublic xmlns="http://www.smpte-ra.org/schemas/430-1/2006/AKDM">
                    <MessageId>{str(uuid.uuid4())}</MessageId>
                    <MessageType>http://www.smpte-ra.org/schemas/430-1/2006/KDM#</MessageType>
                    <CompositionPlaylistId>{cpl_id}</CompositionPlaylistId>
                    <ContentTitleText>{content_title}</ContentTitleText>
                    <ContentKeysNotValidBefore>{valid_from}</ContentKeysNotValidBefore>
                    <ContentKeysNotValidAfter>{valid_until}</ContentKeysNotValidAfter>
                    <Signer>
                      <X509SubjectName>{target_cert.subject.rfc4514_string()}</X509SubjectName>
                      <X509IssuerName>{target_cert.issuer.rfc4514_string()}</X509IssuerName>
                      <X509SerialNumber>{target_cert.serial_number}</X509SerialNumber>
                    </Signer>
                    <Recipient>
                      <X509SubjectName>{target_cert.subject.rfc4514_string()}</X509SubjectName>
                      <X509IssuerName>{target_cert.issuer.rfc4514_string()}</X509IssuerName>
                      <X509SerialNumber>{target_cert.serial_number}</X509SerialNumber>
                    </Recipient>
                    <ContentKeys>
                      <KeyIdList>
                        <TypedKeyId>
                          <KeyId>{key_id}</KeyId>
                          <KeyType>INGEST</KeyType>
                        </TypedKeyId>
                      </KeyIdList>
                    </ContentKeys>
                    <EncryptedTrackFile>
                      <Id>{str(uuid.uuid4())}</Id>
                      <KeyId>{key_id}</KeyId>
                      <CipherData>
                        <CipherValue>{encrypted_key_b64}</CipherValue>
                      </CipherData>
                    </EncryptedTrackFile>
                  </AuthenticatedPublic>
                </DCinemaSecurityMessage>"""
        )
        return kdm_xml

    def save_unsigned_kdm(self, kdm_xml, filename="unsigned_kdm.xml"):
        file_path = self.output_dir / filename
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(kdm_xml)
        return file_path

    def generate_kdm(self, dkdm_path, target_cert_path, start_datetime, end_datetime,
                     content_title, target_timezone=None):
        # Extract info from DKDM
        encrypted_cek, key_id, cpl_id = self.extract_dkdm_info(dkdm_path)

        # Decrypt content key using our private key
        content_key = self.decrypt_content_key(encrypted_cek)

        # Load target certificate
        target_cert = self.load_target_certificate(target_cert_path)

        # Build KDM XML
        kdm_xml = self.build_kdm_xml(
            content_key, key_id, cpl_id, target_cert,
            start_datetime, end_datetime, content_title, target_timezone
        )

        # Save unsigned KDM
        kdm_path = self.save_unsigned_kdm(kdm_xml, "generated_kdm.xml")

        return kdm_path, kdm_xml

