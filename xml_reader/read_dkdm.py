import xml.etree.ElementTree as ET

from exceptions.exceptions import DKDMConformityException
from utils.utils import remove_ns


def parse_xml(xml_path):
    tree = ET.parse(xml_path)

    if tree is None:
        raise DKDMConformityException('DKDM Not Found')

    root = tree.getroot()

    if root.tag != '{http://www.smpte-ra.org/schemas/430-3/2006/ETM}DCinemaSecurityMessage':
        raise DKDMConformityException('DCinemaSecurityMessage must be root element')

    # AuthenticatedPublic / AuthenticatedPrivate / Signature
    mains = [r for r in root]

    mains_as_str = ', '.join(remove_ns(repr(e)) for e in mains)
    err_msg = []

    if 'AuthenticatedPublic' not in mains_as_str:
        err_msg.append('AuhenticatedPublic attribute is mandatory')
    if 'AuthenticatedPrivate' not in mains_as_str:
        err_msg.append('AuthenticatedPrivate attribute is mandatory')
    if 'Signature' not in mains_as_str:
        err_msg.append('Signature attribute is mandatory')

    if err_msg:
        raise DKDMConformityException(','.join(err_msg))

    return mains
