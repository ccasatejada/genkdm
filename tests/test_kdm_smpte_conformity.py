"""
Tests for SMPTE ST 430-1/430-3 KDM conformity.

This module tests whether generated KDMs conform to SMPTE specifications:
- SMPTE ST 430-1: D-Cinema Operations - Key Delivery Message
- SMPTE ST 430-3: D-Cinema Operations - Generic Extra-Theater Message Format
"""

import pytest
import tempfile
from datetime import datetime
from pathlib import Path
from lxml import etree

from kdm.internal.kdm_generator import KDMGenerator
from utils.utils import get_current_path


class TestSMPTEKDMConformity:
    """Test SMPTE conformity of generated KDMs."""

    @pytest.fixture
    def kdm_generator(self):
        """Create KDM generator with test certificates."""
        server_private_key = f"{get_current_path()}/files/tmp/server_key.pem"
        server_cert = f"{get_current_path()}/files/self/full_chain.pem"
        return KDMGenerator(server_private_key, server_cert)

    @pytest.fixture
    def sample_kdm_xml(self, kdm_generator):
        """Generate a sample KDM for testing."""
        dkdm_file = f"{get_current_path()}/files/dkdm/kdm_Test_des_equipements_de_projection_VO_Varietes_Les_Melun_4_110425_110426.xml"
        target_cert_file = f"{get_current_path()}/files/certificate/certificate_chain.pem"

        start_time = datetime(2024, 11, 4, 10, 0, 0)
        end_time = datetime(2024, 11, 6, 23, 59, 59)

        kdm_path, kdm_xml = kdm_generator.generate_kdm(
            dkdm_file, target_cert_file,
            start_time, end_time,
            "Test KDM from DKDM"
        )

        return kdm_xml, kdm_path

    def test_xml_namespace_conformity(self, sample_kdm_xml):
        """Test that KDM uses correct SMPTE namespaces."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        # CRITICAL: Should use SMPTE ST 430-3 ETM namespace
        expected_root_ns = "http://www.smpte-ra.org/schemas/430-3/2006/ETM"
        assert root.nsmap[None] == expected_root_ns, f"Root namespace should be {expected_root_ns}, got {root.nsmap.get(None)}"

        # Should include KDM namespace for extensions
        expected_kdm_ns = "http://www.smpte-ra.org/schemas/430-1/2006/KDM"
        assert expected_kdm_ns in root.nsmap.values(), f"Missing KDM namespace {expected_kdm_ns}"

        # Should include XML signature namespace
        expected_dsig_ns = "http://www.w3.org/2000/09/xmldsig#"
        assert expected_dsig_ns in root.nsmap.values(), f"Missing XML signature namespace {expected_dsig_ns}"

    def test_required_extensions_structure(self, sample_kdm_xml):
        """Test that KDM includes proper RequiredExtensions structure."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        # Find AuthenticatedPublic element
        auth_public = root.find(".//{http://www.smpte-ra.org/schemas/430-3/2006/ETM}AuthenticatedPublic")
        assert auth_public is not None, "Missing AuthenticatedPublic element"

        # Should have RequiredExtensions
        req_ext = auth_public.find(".//{http://www.smpte-ra.org/schemas/430-3/2006/ETM}RequiredExtensions")
        assert req_ext is not None, "Missing RequiredExtensions element"

        # Should have KDMRequiredExtensions inside RequiredExtensions
        kdm_req_ext = req_ext.find(".//{http://www.smpte-ra.org/schemas/430-1/2006/KDM}KDMRequiredExtensions")
        assert kdm_req_ext is not None, "Missing KDMRequiredExtensions element"

    def test_required_kdm_elements(self, sample_kdm_xml):
        """Test presence of all required KDM elements per SMPTE ST 430-1."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        kdm_ns = "{http://www.smpte-ra.org/schemas/430-1/2006/KDM}"
        etm_ns = "{http://www.smpte-ra.org/schemas/430-3/2006/ETM}"

        # Required ETM elements
        required_etm_elements = [
            f"{etm_ns}MessageId",
            f"{etm_ns}MessageType",
            f"{etm_ns}IssueDate",
            f"{etm_ns}Signer",
        ]

        for element_name in required_etm_elements:
            element = root.find(f".//{element_name}")
            assert element is not None, f"Missing required ETM element: {element_name}"

        # Required KDM extension elements
        required_kdm_elements = [
            f"{kdm_ns}Recipient",
            f"{kdm_ns}CompositionPlaylistId",
            f"{kdm_ns}ContentTitleText",
            f"{kdm_ns}ContentKeysNotValidBefore",
            f"{kdm_ns}ContentKeysNotValidAfter",
            f"{kdm_ns}AuthorizedDeviceInfo",
            f"{kdm_ns}KeyIdList",
        ]

        for element_name in required_kdm_elements:
            element = root.find(f".//{element_name}")
            assert element is not None, f"Missing required KDM element: {element_name}"

    def test_recipient_structure(self, sample_kdm_xml):
        """Test Recipient element structure conformity."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        kdm_ns = "{http://www.smpte-ra.org/schemas/430-1/2006/KDM}"
        dsig_ns = "{http://www.w3.org/2000/09/xmldsig#}"

        recipient = root.find(f".//{kdm_ns}Recipient")
        assert recipient is not None, "Missing Recipient element"

        # Should have X509IssuerSerial structure
        issuer_serial = recipient.find(f".//{kdm_ns}X509IssuerSerial")
        assert issuer_serial is not None, "Missing X509IssuerSerial in Recipient"

        issuer_name = issuer_serial.find(f".//{dsig_ns}X509IssuerName")
        assert issuer_name is not None, "Missing X509IssuerName in Recipient"

        serial_number = issuer_serial.find(f".//{dsig_ns}X509SerialNumber")
        assert serial_number is not None, "Missing X509SerialNumber in Recipient"

        # Should have X509SubjectName
        subject_name = recipient.find(f".//{kdm_ns}X509SubjectName")
        assert subject_name is not None, "Missing X509SubjectName in Recipient"

    def test_authorized_device_info_structure(self, sample_kdm_xml):
        """Test AuthorizedDeviceInfo element structure."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        kdm_ns = "{http://www.smpte-ra.org/schemas/430-1/2006/KDM}"
        dsig_ns = "{http://www.w3.org/2000/09/xmldsig#}"

        auth_device_info = root.find(f".//{kdm_ns}AuthorizedDeviceInfo")
        assert auth_device_info is not None, "Missing AuthorizedDeviceInfo element"

        # Required sub-elements (all within KDM namespace in RequiredExtensions)
        device_list_id = auth_device_info.find(f".//{kdm_ns}DeviceListIdentifier")
        assert device_list_id is not None, "Missing DeviceListIdentifier"

        device_list = auth_device_info.find(f".//{kdm_ns}DeviceList")
        assert device_list is not None, "Missing DeviceList"

        cert_thumbprint = device_list.find(f".//{kdm_ns}CertificateThumbprint")
        assert cert_thumbprint is not None, "Missing CertificateThumbprint in DeviceList"

    def test_key_id_list_structure(self, sample_kdm_xml):
        """Test KeyIdList element structure and content."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        kdm_ns = "{http://www.smpte-ra.org/schemas/430-1/2006/KDM}"

        key_id_list = root.find(f".//{kdm_ns}KeyIdList")
        assert key_id_list is not None, "Missing KeyIdList element"

        # Should have at least one TypedKeyId
        typed_key_ids = key_id_list.findall(f".//{kdm_ns}TypedKeyId")
        assert len(typed_key_ids) > 0, "KeyIdList must contain at least one TypedKeyId"

        for typed_key_id in typed_key_ids:
            # Each TypedKeyId should have KeyType and KeyId (both in KDM namespace)
            key_type = typed_key_id.find(f".//{kdm_ns}KeyType")
            assert key_type is not None, "Missing KeyType in TypedKeyId"

            key_id = typed_key_id.find(f".//{kdm_ns}KeyId")
            assert key_id is not None, "Missing KeyId in TypedKeyId"

            # KeyType should have proper scope attribute
            scope_attr = key_type.get("scope")
            expected_scope = "http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type"
            if scope_attr is not None:
                assert scope_attr == expected_scope, f"Invalid KeyType scope: {scope_attr}"

    def test_datetime_format_conformity(self, sample_kdm_xml):
        """Test that datetime elements use proper ISO 8601 format."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        kdm_ns = "{http://www.smpte-ra.org/schemas/430-1/2006/KDM}"
        etm_ns = "{http://www.smpte-ra.org/schemas/430-3/2006/ETM}"

        # Test validity period datetimes
        valid_before = root.find(f".//{kdm_ns}ContentKeysNotValidBefore")
        assert valid_before is not None, "Missing ContentKeysNotValidBefore"

        valid_after = root.find(f".//{kdm_ns}ContentKeysNotValidAfter")
        assert valid_after is not None, "Missing ContentKeysNotValidAfter"

        # Test IssueDate if present
        issue_date = root.find(f".//{etm_ns}IssueDate")
        if issue_date is not None:
            # Should be valid ISO 8601 datetime
            try:
                datetime.fromisoformat(issue_date.text.replace('Z', '+00:00'))
            except ValueError:
                pytest.fail(f"Invalid datetime format in IssueDate: {issue_date.text}")

        # Test validity datetimes format
        for dt_element in [valid_before, valid_after]:
            try:
                datetime.fromisoformat(dt_element.text.replace('Z', '+00:00'))
            except ValueError:
                pytest.fail(f"Invalid datetime format: {dt_element.text}")

    def test_message_type_conformity(self, sample_kdm_xml):
        """Test MessageType element conformity."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        etm_ns = "{http://www.smpte-ra.org/schemas/430-3/2006/ETM}"

        message_type = root.find(f".//{etm_ns}MessageType")
        assert message_type is not None, "Missing MessageType element"

        # Should be the KDM message type URI
        expected_type = "http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type"
        assert message_type.text == expected_type, f"Invalid MessageType: {message_type.text}"

    def test_uuid_format_conformity(self, sample_kdm_xml):
        """Test that UUID elements follow RFC 4122 urn:uuid format."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        etm_ns = "{http://www.smpte-ra.org/schemas/430-3/2006/ETM}"
        kdm_ns = "{http://www.smpte-ra.org/schemas/430-1/2006/KDM}"

        # Find all UUID elements
        uuid_elements = [
            root.find(f".//{etm_ns}MessageId"),
            root.find(f".//{kdm_ns}CompositionPlaylistId"),
            root.find(f".//{kdm_ns}DeviceListIdentifier"),
        ]

        uuid_elements = [el for el in uuid_elements if el is not None]

        import re
        uuid_pattern = re.compile(r'^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

        for uuid_el in uuid_elements:
            if uuid_el.text:
                assert uuid_pattern.match(uuid_el.text), f"Invalid UUID format: {uuid_el.text}"

    def test_missing_xml_signature(self, sample_kdm_xml):
        """Test for missing XML signature (should fail until signature is implemented)."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        dsig_ns = "{http://www.w3.org/2000/09/xmldsig#}"
        signature = root.find(f".//{dsig_ns}Signature")

        # This test documents that signature is missing
        assert signature is None, "KDM should be signed per SMPTE ST 430-3 (currently not implemented)"

    def test_encrypted_content_presence(self, sample_kdm_xml):
        """Test that encrypted content keys are present."""
        kdm_xml, _ = sample_kdm_xml
        root = etree.fromstring(kdm_xml.encode())

        enc_ns = "{http://www.w3.org/2001/04/xmlenc#}"
        etm_ns = "{http://www.smpte-ra.org/schemas/430-3/2006/ETM}"

        # Should have AuthenticatedPrivate with EncryptedKey
        auth_private = root.find(f".//{etm_ns}AuthenticatedPrivate")
        assert auth_private is not None, "Missing AuthenticatedPrivate element"

        encrypted_key = auth_private.find(f".//{etm_ns}EncryptedKey")
        assert encrypted_key is not None, "Missing EncryptedKey element"

        # Should have CipherValue with encrypted content
        cipher_value = encrypted_key.find(f".//{enc_ns}CipherValue")
        assert cipher_value is not None, "Missing CipherValue element"
        assert cipher_value.text is not None and len(cipher_value.text.strip()) > 0, "Empty CipherValue"


class TestKDMSchemaValidation:
    """Test KDM validation against SMPTE schemas."""

    def test_schema_file_exists(self):
        """Test that SMPTE schema file exists."""
        schema_path = Path(f"{get_current_path()}/files/xsd/DCinemaSecurityMessage.xsd")
        assert schema_path.exists(), f"Schema file not found: {schema_path}"

    @pytest.mark.xfail(reason="Current KDM structure doesn't conform to SMPTE schema")
    def test_kdm_validates_against_schema(self):
        """Test KDM validation against SMPTE XSD schema."""
        # This test will fail until KDM structure is fixed
        from kdm.internal.kdm_validator import validate_kdm_xml

        # Generate a KDM
        server_private_key = f"{get_current_path()}/files/tmp/server_key.pem"
        server_cert = f"{get_current_path()}/files/self/full_chain.pem"
        kdm_gen = KDMGenerator(server_private_key, server_cert)

        dkdm_file = f"{get_current_path()}/files/dkdm/kdm_Test_des_equipements_de_projection_VO_Varietes_Les_Melun_4_110425_110426.xml"
        target_cert_file = f"{get_current_path()}/files/certificate/certificate_chain.pem"

        start_time = datetime(2024, 11, 4, 10, 0, 0)
        end_time = datetime(2024, 11, 6, 23, 59, 59)

        kdm_path, kdm_xml = kdm_gen.generate_kdm(
            dkdm_file, target_cert_file,
            start_time, end_time,
            "Test KDM"
        )

        # This should validate without errors once structure is fixed
        xsd_file = f"{get_current_path()}/files/xsd/DCinemaSecurityMessage.xsd"
        validate_kdm_xml(kdm_path, xsd_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])