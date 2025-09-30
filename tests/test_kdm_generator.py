import base64
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from lxml import etree

from kdm.internal.kdm_generator import KDMGenerator


class TestKDMGenerator:

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.server_key_path = Path(self.temp_dir) / "server_key.pem"
        self.server_cert_path = Path(self.temp_dir) / "server_cert.pem"

        with patch('kdm.internal.kdm_generator.get_current_path') as mock_path:
            mock_path.return_value = self.temp_dir
            self.kdm_gen = KDMGenerator(str(self.server_key_path), str(self.server_cert_path))

    def test_init(self):
        assert self.kdm_gen.server_private_key_path == self.server_key_path
        assert self.kdm_gen.server_cert_path == self.server_cert_path
        assert self.kdm_gen.output_dir == Path(f"{self.temp_dir}/files/output")

    def test_extract_dkdm_info(self):
        # mock dkdm xml
        dkdm_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                   <CompositionPlaylistId>test-cpl-id</CompositionPlaylistId>
                   <KeyId>test-key-id</KeyId>
                   <CipherValue>dGVzdC1jaXBoZXItdmFsdWU=</CipherValue>
               </DCinemaSecurityMessage>"""
        )

        with patch('builtins.open', mock_open(read_data=dkdm_xml.encode())):
            encrypted_cek, key_id, cpl_id = self.kdm_gen.extract_dkdm_info("test_path")

        assert encrypted_cek == base64.b64decode("dGVzdC1jaXBoZXItdmFsdWU=")
        assert key_id == "test-key-id"
        assert cpl_id == "test-cpl-id"

    def test_extract_dkdm_info_missing_elements(self):
        # incomplete dkdm xml
        dkdm_xml = (
             """<?xml version="1.0" encoding="UTF-8"?>
                <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                    <CompositionPlaylistId>test-cpl-id</CompositionPlaylistId>
                </DCinemaSecurityMessage>"""
        )

        with patch('builtins.open', mock_open(read_data=dkdm_xml.encode())):
            with pytest.raises(AttributeError):
                self.kdm_gen.extract_dkdm_info("test_path")

    def test_decrypt_content_key(self):
        # Generate test RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Test content key
        test_key = b"test_content_key_16b"

        # Encrypt with public key
        encrypted_key = public_key.encrypt(
            test_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        with patch('builtins.open', mock_open(read_data=b"mock_key_data")):
            with patch('kdm.internal.kdm_generator.load_pem_private_key') as mock_load:
                mock_load.return_value = private_key

                decrypted_key = self.kdm_gen.decrypt_content_key(encrypted_key)

        assert decrypted_key == test_key

    def test_load_target_certificate(self):
        mock_cert_data = b"mock_cert_data"
        mock_cert = Mock()

        with patch('builtins.open', mock_open(read_data=mock_cert_data)):
            with patch('kdm.internal.kdm_generator.x509.load_pem_x509_certificate') as mock_load:
                mock_load.return_value = mock_cert

                cert = KDMGenerator.load_target_certificate("test_path")

        assert cert == mock_cert
        mock_load.assert_called_once_with(mock_cert_data, backend=default_backend())

    def test_encrypt_key_for_target(self):
        # Generate test key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        mock_cert = Mock()
        mock_cert.public_key.return_value = public_key

        test_content_key = b"test_content_key_16b"

        encrypted_b64 = KDMGenerator.encrypt_key_for_target(test_content_key, mock_cert)

        # Verify it's base64 encoded
        encrypted_data = base64.b64decode(encrypted_b64)

        # Verify we can decrypt it back
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        assert decrypted == test_content_key

    def test_get_certificate_thumbprint(self):
        # Create a mock certificate with DER encoding
        mock_cert = Mock()
        test_der_data = b"test_certificate_der_data"
        mock_cert.public_bytes.return_value = test_der_data

        # Calculate expected thumbprint (SHA-1 hash of DER data, base64 encoded)
        import hashlib
        expected_hash = hashlib.sha1(test_der_data).digest()
        expected_thumbprint = base64.b64encode(expected_hash).decode()

        # Test the actual method (can't mock enum members)
        thumbprint = KDMGenerator.get_certificate_thumbprint(mock_cert)

        # Verify that public_bytes was called with DER encoding
        from cryptography.hazmat.primitives.serialization import Encoding
        mock_cert.public_bytes.assert_called_once_with(encoding=Encoding.DER)
        assert thumbprint == expected_thumbprint

    def test_format_datetime_utc_no_timezone(self):
        dt = datetime(2024, 11, 4, 10, 0, 0)
        result = KDMGenerator.format_datetime_utc(dt, None)
        assert result == "2024-11-04T10:00:00Z"

    def test_format_datetime_utc_with_timezone(self):
        dt = datetime(2024, 11, 4, 10, 0, 0)
        tz = timezone.utc
        result = KDMGenerator.format_datetime_utc(dt, tz)
        assert result == "2024-11-04T10:00:00Z"

    def test_build_kdm_xml(self):
        # Mock certificate
        mock_cert = Mock()
        mock_cert.subject.rfc4514_string.return_value = "CN=Test Subject"
        mock_cert.issuer.rfc4514_string.return_value = "CN=Test Issuer"
        mock_cert.serial_number = 12345

        test_content_key = b"test_content_key_16b"
        key_id = "urn:uuid:test-key-id"  # Use proper UUID format
        cpl_id = "urn:uuid:test-cpl-id"  # Use proper UUID format
        start_dt = datetime(2024, 11, 4, 10, 0, 0)
        end_dt = datetime(2024, 11, 6, 23, 59, 59)
        title = "Test Content"

        with patch.object(self.kdm_gen, 'encrypt_key_for_target') as mock_encrypt, \
             patch.object(self.kdm_gen, 'get_certificate_thumbprint') as mock_thumbprint:
            mock_encrypt.return_value = "encrypted_key_b64"
            mock_thumbprint.return_value = "test_thumbprint"

            kdm_xml = self.kdm_gen.build_kdm_xml(
                test_content_key, key_id, cpl_id, mock_cert,
                start_dt, end_dt, title
            )

        # Parse and verify XML structure
        root = etree.fromstring(kdm_xml.encode('utf-8'))
        assert root.tag.endswith("DCinemaSecurityMessage")

        # Check SMPTE-compliant namespace
        assert root.nsmap[None] == "http://www.smpte-ra.org/schemas/430-3/2006/ETM"

        # Check KDM content in proper namespace
        kdm_ns = "{http://www.smpte-ra.org/schemas/430-1/2006/KDM}"
        assert root.findtext(f".//{kdm_ns}CompositionPlaylistId") == cpl_id
        assert root.findtext(f".//{kdm_ns}ContentTitleText") == title
        assert root.findtext(f".//{kdm_ns}KeyId") == key_id

        # Check encrypted content
        enc_ns = "{http://www.w3.org/2001/04/xmlenc#}"
        assert root.findtext(f".//{enc_ns}CipherValue") == "encrypted_key_b64"

    def test_save_unsigned_kdm(self):
        test_xml = "<test>xml</test>"
        filename = "test_kdm.xml"

        # Ensure output directory exists
        self.kdm_gen.output_dir.mkdir(parents=True, exist_ok=True)

        result_path = self.kdm_gen.save_unsigned_kdm(test_xml, filename)

        assert result_path == self.kdm_gen.output_dir / filename
        self.exists = result_path.exists()
        assert self.exists
        assert result_path.read_text(encoding="utf-8") == test_xml

    @patch.object(KDMGenerator, 'extract_dkdm_info')
    @patch.object(KDMGenerator, 'decrypt_content_key')
    @patch.object(KDMGenerator, 'load_target_certificate')
    @patch.object(KDMGenerator, 'build_kdm_xml')
    @patch.object(KDMGenerator, 'save_unsigned_kdm')
    def test_generate_kdm_integration(self, mock_save, mock_build, mock_load_cert,
                                      mock_decrypt, mock_extract):
        # Setup mocks
        mock_extract.return_value = (b"encrypted_key", "key-id", "cpl-id")
        mock_decrypt.return_value = b"decrypted_content_key"
        mock_cert = Mock()
        mock_load_cert.return_value = mock_cert
        mock_build.return_value = "<kdm>xml</kdm>"
        mock_save.return_value = Path("/test/output/generated_kdm.xml")

        # Test data
        dkdm_path = "/test/dkdm.xml"
        target_cert_path = "/test/target_cert.pem"
        start_dt = datetime(2024, 11, 4, 10, 0, 0)
        end_dt = datetime(2024, 11, 6, 23, 59, 59)
        title = "Test KDM"

        # Execute
        kdm_path, kdm_xml = self.kdm_gen.generate_kdm(
            dkdm_path, target_cert_path, start_dt, end_dt, title
        )

        # Verify calls
        mock_extract.assert_called_once_with(dkdm_path)
        mock_decrypt.assert_called_once_with(b"encrypted_key")
        mock_load_cert.assert_called_once_with(target_cert_path)
        mock_build.assert_called_once_with(
            b"decrypted_content_key", "key-id", "cpl-id", mock_cert,
            start_dt, end_dt, title, None
        )
        mock_save.assert_called_once_with("<kdm>xml</kdm>", "generated_kdm.xml")

        assert kdm_path == Path("/test/output/generated_kdm.xml")
        assert kdm_xml == "<kdm>xml</kdm>"

    def test_generate_kdm_with_timezone(self):
        with patch.object(self.kdm_gen, 'extract_dkdm_info') as mock_extract, \
                patch.object(self.kdm_gen, 'decrypt_content_key') as mock_decrypt, \
                patch.object(self.kdm_gen, 'load_target_certificate') as mock_load_cert, \
                patch.object(self.kdm_gen, 'build_kdm_xml') as mock_build, \
                patch.object(self.kdm_gen, 'save_unsigned_kdm') as mock_save:
            mock_extract.return_value = (b"encrypted_key", "key-id", "cpl-id")
            mock_decrypt.return_value = b"decrypted_content_key"
            mock_cert = Mock()
            mock_load_cert.return_value = mock_cert
            mock_build.return_value = "<kdm>xml</kdm>"
            mock_save.return_value = Path("/test/output/generated_kdm.xml")

            target_tz = timezone.utc

            self.kdm_gen.generate_kdm(
                "/test/dkdm.xml", "/test/cert.pem",
                datetime(2024, 11, 4), datetime(2024, 11, 6),
                "Test", target_tz
            )

            # Verify timezone was passed to build_kdm_xml
            call_args = mock_build.call_args
            assert call_args[0][7] == target_tz  # 8th argument (0-indexed 7) is target_timezone
