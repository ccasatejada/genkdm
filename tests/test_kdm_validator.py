import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from kdm.internal.kdm_validator import validate_kdm_xml, check_kdm_against_cpl


class TestKDMValidator:

    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()

    def test_validate_kdm_xml_success(self):
        # Create real temporary files for testing
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

        valid_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
                <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                    <MessageId>test-id</MessageId>
                </DCinemaSecurityMessage>"""
        )

        xsd_path = Path(self.temp_dir) / "test.xsd"
        xml_path = Path(self.temp_dir) / "test.xml"

        with open(xsd_path, 'w', encoding='utf-8') as f:
            f.write(xsd_content)
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write(valid_xml)

        with patch('builtins.print') as mock_print:
            result = validate_kdm_xml(str(xml_path), str(xsd_path))

        assert result is True

    def test_validate_kdm_xml_failure(self):
        # Create XSD and invalid XML
        xsd_content = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
                          targetNamespace="http://www.smpte-ra.org/schemas/430-1/2006/DS"
                          xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS"
                          elementFormDefault="qualified">
                   <xs:element name="DCinemaSecurityMessage">
                       <xs:complexType>
                           <xs:sequence>
                               <xs:element name="MessageId" type="xs:string"/>
                           </xs:sequence>
                       </xs:complexType>
                   </xs:element>
               </xs:schema>"""
        )

        invalid_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
                <WrongRoot xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                    <MessageId>test-id</MessageId>
                </WrongRoot>"""
        )

        xsd_path = Path(self.temp_dir) / "test.xsd"
        xml_path = Path(self.temp_dir) / "test.xml"

        with open(xsd_path, 'w', encoding='utf-8') as f:
            f.write(xsd_content)
        with open(xml_path, 'w', encoding='utf-8') as f:
            f.write(invalid_xml)

        with patch('builtins.print') as mock_print:
            result = validate_kdm_xml(str(xml_path), str(xsd_path))

        assert result is False

    def test_validate_kdm_xml_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            validate_kdm_xml("nonexistent_xml", "nonexistent_xsd")

    def test_check_kdm_against_cpl_success(self):
        # Create CPL and KDM files
        cpl_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/429-7/2006/CPL" Id="test-cpl-id">
                   <KeyIdList>
                       <KeyId>key-1</KeyId>
                       <KeyId>key-2</KeyId>
                   </KeyIdList>
               </CompositionPlaylist>"""
        )

        kdm_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                   <CompositionPlaylistId>test-cpl-id</CompositionPlaylistId>
                   <KeyId>key-1</KeyId>
                   <KeyId>key-2</KeyId>
               </DCinemaSecurityMessage>"""
        )

        cpl_path = Path(self.temp_dir) / "test.cpl"
        kdm_path = Path(self.temp_dir) / "test.kdm"

        with open(cpl_path, 'w', encoding='utf-8') as f:
            f.write(cpl_xml)
        with open(kdm_path, 'w', encoding='utf-8') as f:
            f.write(kdm_xml)

        with patch('builtins.print') as mock_print:
            result = check_kdm_against_cpl(str(kdm_path), str(cpl_path))

        assert result is True

    def test_check_kdm_against_cpl_cpl_id_mismatch(self):
        # Create CPL and KDM with mismatched IDs
        cpl_xml = (
        """<?xml version="1.0" encoding="UTF-8"?>
           <CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/429-7/2006/CPL" Id="different-cpl-id">
               <KeyIdList>
                   <KeyId>key-1</KeyId>
               </KeyIdList>
           </CompositionPlaylist>"""
        )

        kdm_xml = (
             """<?xml version="1.0" encoding="UTF-8"?>
                <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                    <CompositionPlaylistId>test-cpl-id</CompositionPlaylistId>
                    <KeyId>key-1</KeyId>
                </DCinemaSecurityMessage>"""
        )

        cpl_path = Path(self.temp_dir) / "test.cpl"
        kdm_path = Path(self.temp_dir) / "test.kdm"

        with open(cpl_path, 'w', encoding='utf-8') as f:
            f.write(cpl_xml)
        with open(kdm_path, 'w', encoding='utf-8') as f:
            f.write(kdm_xml)

        with patch('builtins.print') as mock_print:
            result = check_kdm_against_cpl(str(kdm_path), str(cpl_path))

        assert result is False

    def test_check_kdm_against_cpl_key_not_found(self):
        # Create CPL with limited keys and KDM with extra key
        cpl_xml = (
             """<?xml version="1.0" encoding="UTF-8"?>
                <CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/429-7/2006/CPL" Id="test-cpl-id">
                    <KeyIdList>
                        <KeyId>key-1</KeyId>
                    </KeyIdList>
                </CompositionPlaylist>"""
        )

        kdm_xml = (
        """<?xml version="1.0" encoding="UTF-8"?>
           <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
               <CompositionPlaylistId>test-cpl-id</CompositionPlaylistId>
               <KeyId>key-1</KeyId>
               <KeyId>key-2</KeyId>
           </DCinemaSecurityMessage>"""
        )

        cpl_path = Path(self.temp_dir) / "test.cpl"
        kdm_path = Path(self.temp_dir) / "test.kdm"

        with open(cpl_path, 'w', encoding='utf-8') as f:
            f.write(cpl_xml)
        with open(kdm_path, 'w', encoding='utf-8') as f:
            f.write(kdm_xml)

        with patch('builtins.print') as mock_print:
            result = check_kdm_against_cpl(str(kdm_path), str(cpl_path))

        assert result is False

    def test_check_kdm_against_cpl_no_namespace(self):
        # Create CPL without default namespace
        cpl_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <CompositionPlaylist Id="test-cpl-id">
                   <KeyIdList>
                       <KeyId>key-1</KeyId>
                   </KeyIdList>
               </CompositionPlaylist>"""
        )

        kdm_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                   <CompositionPlaylistId>test-cpl-id</CompositionPlaylistId>
                   <KeyId>key-1</KeyId>
               </DCinemaSecurityMessage>"""
        )

        cpl_path = Path(self.temp_dir) / "test.cpl"
        kdm_path = Path(self.temp_dir) / "test.kdm"

        with open(cpl_path, 'w', encoding='utf-8') as f:
            f.write(cpl_xml)
        with open(kdm_path, 'w', encoding='utf-8') as f:
            f.write(kdm_xml)

        # This should handle the case where CPL has no default namespace
        with pytest.raises(KeyError):
            check_kdm_against_cpl(str(kdm_path), str(cpl_path))

    def test_check_kdm_against_cpl_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            check_kdm_against_cpl("nonexistent_kdm", "nonexistent_cpl")

    def test_check_kdm_against_cpl_empty_key_lists(self):
        # Create CPL and KDM with no keys
        cpl_xml = (
            """<?xml version="1.0" encoding="UTF-8"?>
               <CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/429-7/2006/CPL" Id="test-cpl-id">
               </CompositionPlaylist>"""
        )
        kdm_xml = (
              """<?xml version="1.0" encoding="UTF-8"?>
                 <DCinemaSecurityMessage xmlns="http://www.smpte-ra.org/schemas/430-1/2006/DS">
                     <CompositionPlaylistId>test-cpl-id</CompositionPlaylistId>
                 </DCinemaSecurityMessage>"""
        )

        cpl_path = Path(self.temp_dir) / "test.cpl"
        kdm_path = Path(self.temp_dir) / "test.kdm"

        with open(cpl_path, 'w', encoding='utf-8') as f:
            f.write(cpl_xml)
        with open(kdm_path, 'w', encoding='utf-8') as f:
            f.write(kdm_xml)

        with patch('builtins.print') as mock_print:
            result = check_kdm_against_cpl(str(kdm_path), str(cpl_path))

        assert result is True
