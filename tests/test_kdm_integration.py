import base64
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from lxml import etree

from kdm.internal.kdm_generator import KDMGenerator
from kdm.internal.kdm_validator import validate_kdm_xml, check_kdm_against_cpl


class TestKDMIntegration:

    def setup_method(self):
        # Create temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.files_dir = Path(self.temp_dir) / "files"

        # Create directory structure
        (self.files_dir / "tmp").mkdir(parents=True, exist_ok=True)
        (self.files_dir / "self").mkdir(parents=True, exist_ok=True)
        (self.files_dir / "dkdm").mkdir(parents=True, exist_ok=True)
        (self.files_dir / "certificate").mkdir(parents=True, exist_ok=True)
        (self.files_dir / "cpl").mkdir(parents=True, exist_ok=True)
        (self.files_dir / "xsd").mkdir(parents=True, exist_ok=True)
        (self.files_dir / "output").mkdir(parents=True, exist_ok=True)

    def create_test_rsa_key_pair(self):
        """Generate RSA key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    def create_test_certificate(self, private_key, subject_name="CN=Test Certificate"):
        """Create a test X.509 certificate."""
        from cryptography.x509.oid import NameOID
        from cryptography import x509
        import datetime

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            12345
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256(), backend=default_backend())

        return cert

    def create_test_dkdm(self, server_public_key, cpl_id="test-cpl-id", key_id="test-key-id"):
        """Create a test DKDM file with encrypted content key."""
        # Test content key
        content_key = b"test_content_key_16b"

        # Encrypt content key with server public key
        from cryptography.hazmat.primitives.asymmetric import padding
        encrypted_key = server_public_key.encrypt(
            content_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

        dkdm_xml = (
            f"""<?xml version="1.0" encoding="UTF-8"?>
                <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                    <AuthenticatedPublic xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DKDM">
                        <MessageId>test-message-id</MessageId>
                        <MessageType>http://www.smpte-ra.org/schemas/430-1/2006/DKDM#</MessageType>
                        <CompositionPlaylistId>{cpl_id}</CompositionPlaylistId>
                        <ContentTitleText>Test DKDM Content</ContentTitleText>
                        <KeyId>{key_id}</KeyId>
                        <CipherData>
                            <CipherValue>{encrypted_key_b64}</CipherValue>
                        </CipherData>
                    </AuthenticatedPublic>
                </DCinemaSecurityMessage>"""
        )

        return dkdm_xml, content_key

    def create_test_cpl(self, cpl_id="test-cpl-id", key_ids=None):
        """Create a test CPL file."""
        if key_ids is None:
            key_ids = ["test-key-id"]

        key_id_elements = "\n".join([f"<KeyId>{kid}</KeyId>" for kid in key_ids])

        cpl_xml = (
            f"""<?xml version="1.0" encoding="UTF-8"?>
                <CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/429-7/2006/CPL" Id="{cpl_id}">
                    <Id>{cpl_id}</Id>
                    <AnnotationText>Test CPL</AnnotationText>
                    <IssueDate>2024-01-01T00:00:00Z</IssueDate>
                    <Issuer>Test Issuer</Issuer>
                    <Creator>Test Creator</Creator>
                    <ContentTitleText>Test Content</ContentTitleText>
                    <ContentKind>feature</ContentKind>
                    <ContentVersion>
                        <Id>test-version-id</Id>
                        <LabelText>Version 1</LabelText>
                    </ContentVersion>
                    <ReelList>
                        <Reel>
                            <Id>test-reel-id</Id>
                            <AssetList>
                                <MainPicture>
                                    <Id>test-picture-id</Id>
                                    <KeyId>{key_ids[0] if key_ids else 'test-key-id'}</KeyId>
                                </MainPicture>
                            </AssetList>
                        </Reel>
                    </ReelList>
                    <KeyIdList>
                        {key_id_elements}
                    </KeyIdList>
                </CompositionPlaylist>"""
        )

        return cpl_xml

    def create_simple_xsd(self):
        """Create a simplified XSD for testing."""
        xsd_content = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
                          targetNamespace="http://www.smpte-ra.org/schemas/430-1/2006/DS"
                          xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS"
                          elementFormDefault="qualified">
               
                   <xs:element name="DCinemaSecurityMessage">
                       <xs:complexType>
                           <xs:sequence>
                               <xs:any processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
                           </xs:sequence>
                       </xs:complexType>
                   </xs:element>
               </xs:schema>"""
        )
        return xsd_content

    @patch('kdm.internal.kdm_generator.get_current_path')
    def test_full_kdm_generation_workflow(self, mock_get_path):
        """Test the complete KDM generation workflow from DKDM to validated KDM."""
        mock_get_path.return_value = str(self.temp_dir)

        # Generate server key pair
        server_private_key, server_public_key = self.create_test_rsa_key_pair()
        server_cert = self.create_test_certificate(server_private_key, "CN=Test Server")

        # Generate target key pair and certificate
        target_private_key, target_public_key = self.create_test_rsa_key_pair()
        target_cert = self.create_test_certificate(target_private_key, "CN=Test Target")

        # Create test files
        cpl_id = "test-cpl-id-12345"
        key_id = "test-key-id-67890"

        dkdm_xml, original_content_key = self.create_test_dkdm(
            server_public_key, cpl_id, key_id
        )
        cpl_xml = self.create_test_cpl(cpl_id, [key_id])
        xsd_content = self.create_simple_xsd()

        # Write test files
        server_key_path = self.files_dir / "tmp" / "server_key.pem"
        server_cert_path = self.files_dir / "self" / "full_chain.pem"
        target_cert_path = self.files_dir / "certificate" / "certificate_chain.pem"
        dkdm_path = self.files_dir / "dkdm" / "test_dkdm.xml"
        cpl_path = self.files_dir / "cpl" / "test_cpl.xml"
        xsd_path = self.files_dir / "xsd" / "DCinemaSecurityMessage.xsd"

        with open(server_key_path, "wb") as f:
            f.write(server_private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

        with open(server_cert_path, "wb") as f:
            f.write(server_cert.public_bytes(Encoding.PEM))

        with open(target_cert_path, "wb") as f:
            f.write(target_cert.public_bytes(Encoding.PEM))

        with open(dkdm_path, "w", encoding="utf-8") as f:
            f.write(dkdm_xml)

        with open(cpl_path, "w", encoding="utf-8") as f:
            f.write(cpl_xml)

        with open(xsd_path, "w", encoding="utf-8") as f:
            f.write(xsd_content)

        # Initialize KDM generator
        kdm_gen = KDMGenerator(str(server_key_path), str(server_cert_path))

        # Generate KDM
        start_time = datetime(2024, 11, 4, 10, 0, 0)
        end_time = datetime(2024, 11, 6, 23, 59, 59)

        kdm_path, kdm_xml = kdm_gen.generate_kdm(
            str(dkdm_path),
            str(target_cert_path),
            start_time,
            end_time,
            "Integration Test KDM"
        )

        # Verify KDM was generated
        assert kdm_path.exists()
        assert kdm_xml is not None

        # Parse and validate KDM structure
        kdm_root = etree.fromstring(kdm_xml.encode('utf-8'))
        assert kdm_root.tag.endswith("DCinemaSecurityMessage")
        assert kdm_root.findtext(".//{*}CompositionPlaylistId") == cpl_id
        assert kdm_root.findtext(".//{*}ContentTitleText") == "Integration Test KDM"
        assert kdm_root.findtext(".//{*}KeyId") == key_id

        # Verify encrypted key can be decrypted by target
        cipher_value = kdm_root.findtext(".//{*}CipherValue")
        assert cipher_value is not None

        encrypted_key_data = base64.b64decode(cipher_value)
        from cryptography.hazmat.primitives.asymmetric import padding
        decrypted_key = target_private_key.decrypt(
            encrypted_key_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        assert decrypted_key == original_content_key

        # Validate KDM against XSD
        with patch('builtins.print'):  # Suppress print statements during test
            validation_result = validate_kdm_xml(str(kdm_path), str(xsd_path))
        assert validation_result is True

        # Check KDM against CPL
        with patch('builtins.print'):  # Suppress print statements during test
            cpl_check_result = check_kdm_against_cpl(str(kdm_path), str(cpl_path))
        assert cpl_check_result is True

    @patch('kdm.internal.kdm_generator.get_current_path')
    def test_kdm_generation_with_multiple_keys(self, mock_get_path):
        """Test KDM generation with multiple keys."""
        mock_get_path.return_value = str(self.temp_dir)

        # Generate server key pair
        server_private_key, server_public_key = self.create_test_rsa_key_pair()
        target_private_key, target_public_key = self.create_test_rsa_key_pair()
        target_cert = self.create_test_certificate(target_private_key, "CN=Test Target")

        # Create files
        server_key_path = self.files_dir / "tmp" / "server_key.pem"
        target_cert_path = self.files_dir / "certificate" / "certificate_chain.pem"

        with open(server_key_path, "wb") as f:
            f.write(server_private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

        with open(target_cert_path, "wb") as f:
            f.write(target_cert.public_bytes(Encoding.PEM))

        # Test with multiple key IDs
        cpl_id = "multi-key-cpl"
        key_ids = ["key-1", "key-2", "key-3"]

        for key_id in key_ids:
            dkdm_xml, _ = self.create_test_dkdm(server_public_key, cpl_id, key_id)
            dkdm_path = self.files_dir / "dkdm" / f"test_dkdm_{key_id}.xml"

            with open(dkdm_path, "w", encoding="utf-8") as f:
                f.write(dkdm_xml)

            kdm_gen = KDMGenerator(str(server_key_path), "dummy_cert_path")

            kdm_path, kdm_xml = kdm_gen.generate_kdm(
                str(dkdm_path),
                str(target_cert_path),
                datetime(2024, 11, 4),
                datetime(2024, 11, 6),
                f"Test KDM for {key_id}"
            )

            # Verify each KDM has the correct key ID
            kdm_root = etree.fromstring(kdm_xml.encode('utf-8'))
            assert kdm_root.findtext(".//{*}KeyId") == key_id
            assert kdm_root.findtext(".//{*}CompositionPlaylistId") == cpl_id

    @patch('kdm.internal.kdm_generator.get_current_path')
    def test_kdm_generation_error_handling(self, mock_get_path):
        """Test error handling in KDM generation workflow."""
        mock_get_path.return_value = str(self.temp_dir)

        # Test with non-existent DKDM file
        kdm_gen = KDMGenerator("dummy_key", "dummy_cert")

        with pytest.raises(FileNotFoundError):
            kdm_gen.generate_kdm(
                "nonexistent_dkdm.xml",
                "nonexistent_cert.pem",
                datetime(2024, 11, 4),
                datetime(2024, 11, 6),
                "Test KDM"
            )

    @patch('kdm.internal.kdm_generator.get_current_path')
    def test_kdm_datetime_formatting(self, mock_get_path):
        """Test datetime formatting in KDM generation."""
        mock_get_path.return_value = str(self.temp_dir)

        server_private_key, server_public_key = self.create_test_rsa_key_pair()
        target_private_key, target_public_key = self.create_test_rsa_key_pair()
        target_cert = self.create_test_certificate(target_private_key, "CN=Test Target")

        # Create minimal test files
        server_key_path = self.files_dir / "tmp" / "server_key.pem"
        target_cert_path = self.files_dir / "certificate" / "certificate_chain.pem"

        with open(server_key_path, "wb") as f:
            f.write(server_private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

        with open(target_cert_path, "wb") as f:
            f.write(target_cert.public_bytes(Encoding.PEM))

        dkdm_xml, _ = self.create_test_dkdm(server_public_key)
        dkdm_path = self.files_dir / "dkdm" / "test_dkdm.xml"

        with open(dkdm_path, "w", encoding="utf-8") as f:
            f.write(dkdm_xml)

        kdm_gen = KDMGenerator(str(server_key_path), "dummy_cert")

        # Test specific datetime formatting
        start_time = datetime(2024, 12, 25, 14, 30, 45)
        end_time = datetime(2024, 12, 26, 23, 59, 59)

        kdm_path, kdm_xml = kdm_gen.generate_kdm(
            str(dkdm_path),
            str(target_cert_path),
            start_time,
            end_time,
            "DateTime Test KDM"
        )

        kdm_root = etree.fromstring(kdm_xml.encode('utf-8'))

        # Verify datetime formatting
        not_valid_before = kdm_root.findtext(".//{*}ContentKeysNotValidBefore")
        not_valid_after = kdm_root.findtext(".//{*}ContentKeysNotValidAfter")

        assert not_valid_before == "2024-12-25T14:30:45Z"
        assert not_valid_after == "2024-12-26T23:59:59Z"
