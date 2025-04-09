import pytest
import xml.etree.ElementTree as ET

from xml_reader import read_dkdm


def test_parse_xml():
    """
    test that read_dkdm.parse_xml do not throw any exception and return list
    :return:
    """
    mains = read_dkdm.parse_xml('../files/dkdm/any_dkdm_file.xml')
    assert len(mains) == 3, "function must return list with 3 items"