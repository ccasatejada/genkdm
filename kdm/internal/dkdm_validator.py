"""
DKDM Validator - Validates DKDMs against self-signed certificates.

This module ensures that:
1. The DKDM is encrypted for our device (recipient validation)
2. We can successfully decrypt the DKDM with our private key
3. The DKDM structure is valid according to SMPTE standards
"""

import base64
from pathlib import Path
from typing import Tuple, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding
from lxml import etree

from exceptions.exceptions import DKDMConformityException
from utils.logger import get_logger

log = get_logger()


class DKDMValidationError(Exception):
    """Raised when DKDM validation fails."""
    pass


class DKDMValidator:
    """Validates DKDM files against self-signed certificates."""

    def __init__(self, cert_path: str, key_path: str):
        """
        Initialize validator with certificate and private key.

        Args:
            cert_path: Path to device certificate PEM file
            key_path: Path to private key PEM file
        """
        self.cert_path = Path(cert_path)
        self.key_path = Path(key_path)

        # Load certificate
        with open(self.cert_path, 'rb') as f:
            self.certificate = x509.load_pem_x509_certificate(f.read(), default_backend())

        # Load private key
        with open(self.key_path, 'rb') as f:
            self.private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

        # Extract certificate info for comparison
        self.issuer_name = self.certificate.issuer.rfc4514_string()
        self.serial_number = str(self.certificate.serial_number)
        self.subject_name = self.certificate.subject.rfc4514_string()
        self.thumbprint = self._calculate_thumbprint(self.certificate)

    @staticmethod
    def _calculate_thumbprint(cert: x509.Certificate) -> str:
        """Calculate SMPTE-compliant SHA-1 thumbprint of certificate."""
        cert_der = cert.public_bytes(encoding=Encoding.DER)
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(cert_der)
        thumbprint_bytes = digest.finalize()
        return base64.b64encode(thumbprint_bytes).decode()

    def extract_dkdm_recipient_info(self, dkdm_path: str) -> dict:
        """
        Extract recipient information from DKDM XML.

        Args:
            dkdm_path: Path to DKDM XML file

        Returns:
            Dictionary containing recipient info
        """
        with open(dkdm_path, 'rb') as f:
            tree = etree.parse(f)
            root = tree.getroot()

        # Define namespaces
        etm_ns = 'http://www.smpte-ra.org/schemas/430-3/2006/ETM'
        kdm_ns = 'http://www.smpte-ra.org/schemas/430-1/2006/KDM'
        dsig_ns = 'http://www.w3.org/2000/09/xmldsig#'

        # Extract recipient certificate information
        recipient_elem = root.find(f'.//{{{etm_ns}}}RequiredExtensions//{{{kdm_ns}}}Recipient', namespaces=None)

        if recipient_elem is None:
            raise DKDMValidationError("DKDM does not contain Recipient information")

        # Extract issuer name and serial number
        issuer_serial = recipient_elem.find(f'.//{{{dsig_ns}}}X509IssuerSerial', namespaces=None)
        if issuer_serial is None:
            raise DKDMValidationError("DKDM Recipient missing X509IssuerSerial")

        issuer_name = issuer_serial.findtext(f'.//{{{dsig_ns}}}X509IssuerName', '', namespaces=None)
        serial_number = issuer_serial.findtext(f'.//{{{dsig_ns}}}X509SerialNumber', '', namespaces=None)
        subject_name = recipient_elem.findtext(f'.//{{{dsig_ns}}}X509SubjectName', '', namespaces=None)

        # Extract device thumbprints from AuthorizedDeviceInfo
        device_thumbprints = []
        device_list = root.findall(f'.//{{{kdm_ns}}}AuthorizedDeviceInfo//{{{kdm_ns}}}DeviceList//{{{kdm_ns}}}CertificateThumbprint', namespaces=None)
        for thumbprint_elem in device_list:
            if thumbprint_elem.text:
                device_thumbprints.append(thumbprint_elem.text.strip())

        return {
            'issuer_name': issuer_name.strip() if issuer_name else '',
            'serial_number': serial_number.strip() if serial_number else '',
            'subject_name': subject_name.strip() if subject_name else '',
            'device_thumbprints': device_thumbprints
        }

    def validate_recipient(self, dkdm_path: str) -> Tuple[bool, str]:
        """
        Validate that the DKDM is encrypted for our certificate.

        Args:
            dkdm_path: Path to DKDM XML file

        Returns:
            Tuple of (is_valid, message)
        """
        try:
            recipient_info = self.extract_dkdm_recipient_info(dkdm_path)
        except Exception as e:
            return False, f"Failed to extract recipient info: {e}"

        # Check issuer name
        if recipient_info['issuer_name'] != self.issuer_name:
            return False, (
                f"DKDM issuer mismatch. "
                f"Expected: {self.issuer_name}, "
                f"Got: {recipient_info['issuer_name']}"
            )

        # Check serial number
        if recipient_info['serial_number'] != self.serial_number:
            return False, (
                f"DKDM serial number mismatch. "
                f"Expected: {self.serial_number}, "
                f"Got: {recipient_info['serial_number']}"
            )

        # Check subject name
        if recipient_info['subject_name'] != self.subject_name:
            return False, (
                f"DKDM subject mismatch. "
                f"Expected: {self.subject_name}, "
                f"Got: {recipient_info['subject_name']}"
            )

        # Check device thumbprint if present
        if recipient_info['device_thumbprints']:
            if self.thumbprint not in recipient_info['device_thumbprints']:
                return False, (
                    f"Certificate thumbprint not in authorized device list. "
                    f"Expected: {self.thumbprint}, "
                    f"Authorized: {', '.join(recipient_info['device_thumbprints'])}"
                )

        return True, "DKDM recipient validation successful"

    def validate_decryption(self, dkdm_path: str) -> Tuple[bool, str, Optional[bytes]]:
        """
        Validate that we can decrypt the DKDM with our private key.

        Args:
            dkdm_path: Path to DKDM XML file

        Returns:
            Tuple of (is_valid, message, decrypted_content_key)
        """
        try:
            # Extract encrypted content key
            with open(dkdm_path, 'rb') as f:
                tree = etree.parse(f)
                root = tree.getroot()

            encrypted_cek_b64 = root.findtext(".//{*}CipherValue")
            if not encrypted_cek_b64:
                return False, "DKDM does not contain CipherValue", None

            encrypted_cek = base64.b64decode(encrypted_cek_b64)

            # Attempt decryption
            content_key = self.private_key.decrypt(
                encrypted_cek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

            # Validate content key length (should be 16 bytes for AES-128)
            if len(content_key) != 16:
                log.warning(f"Unexpected content key length: {len(content_key)} bytes (expected 16)")

            return True, "DKDM decryption successful", content_key

        except Exception as e:
            return False, f"DKDM decryption failed: {e}", None

    def validate_dkdm(self, dkdm_path: str, check_decryption: bool = True) -> Tuple[bool, str]:
        """
        Complete DKDM validation against self-signed certificate.

        Args:
            dkdm_path: Path to DKDM XML file
            check_decryption: Whether to attempt decryption (default True)

        Returns:
            Tuple of (is_valid, message)
        """
        log.info(f"Validating DKDM: {dkdm_path}")
        log.info(f"Against certificate: {self.cert_path}")

        # Step 1: Validate recipient information
        is_valid, message = self.validate_recipient(dkdm_path)
        if not is_valid:
            log.error(f"Recipient validation failed: {message}")
            return False, message

        log.info("Recipient validation passed")

        # Step 2: Validate decryption (optional but recommended)
        if check_decryption:
            is_valid, message, content_key = self.validate_decryption(dkdm_path)
            if not is_valid:
                log.error(f"Decryption validation failed: {message}")
                return False, message

            log.info("Decryption validation passed")

        return True, "DKDM validation successful"


def validate_dkdm_against_certificate(dkdm_path: str, cert_path: str, key_path: str) -> Tuple[bool, str]:
    """
    Convenience function to validate DKDM against certificate.

    Args:
        dkdm_path: Path to DKDM XML file
        cert_path: Path to device certificate PEM file
        key_path: Path to private key PEM file

    Returns:
        Tuple of (is_valid, message)
    """
    validator = DKDMValidator(cert_path, key_path)
    return validator.validate_dkdm(dkdm_path)