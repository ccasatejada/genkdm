import pytest
import xml.etree.ElementTree as ET

from xml_reader import read_dkdm


def test_parse_xml():
    """
    test that read_dkdm.parse_xml do not throw any exception and return list
    :return:
    """
    mains = read_dkdm.parse_xml('../files/dkdm/DKDM_Pachamama_FTR-1_F_FR-XX_FR_51-VI_2K_FOLI_20181113_HVY_IOP_OV.xml')
    assert len(mains) == 3, "function must return list with 3 items"