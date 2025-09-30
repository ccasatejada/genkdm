from lxml import etree

from utils.logger import get_logger

log = get_logger()


def validate_kdm_xml(xml_path, xsd_path):
    with open(xsd_path, 'rb') as f:
        xsd_doc = etree.parse(f)
        xsd_schema = etree.XMLSchema(xsd_doc)

    with open(xml_path, 'rb') as f:
        xml_doc = etree.parse(f)

    if xsd_schema.validate(xml_doc):
        log.info("KDM XML is valid according to SMPTE XSD")
        return True
    else:
        log.info("KDM XML validation failed")
        for error in xsd_schema.error_log:
            log.info(f"  \u21aa\ufe0f {error.message}")
        return False


def check_kdm_against_cpl(kdm_xml_path, cpl_path):
    with open(cpl_path, "rb") as f:
        cpl_tree = etree.parse(f)
        cpl_root = cpl_tree.getroot()
        nsmap = {"ns": cpl_root.nsmap[None]}
        cpl_id = cpl_root.get("Id")
        cpl_key_ids = [e.text for e in cpl_tree.xpath("//ns:KeyId", namespaces=nsmap)]

    with open(kdm_xml_path, "rb") as f:
        kdm_tree = etree.parse(f)
        kdm_root = kdm_tree.getroot()
        kdm_cpl_id = kdm_root.findtext(".//{*}CompositionPlaylistId")
        kdm_key_ids = [el.text for el in kdm_tree.findall(".//{*}KeyId")]

    log.info("Checking KDM against CPL...")
    cpl_match = cpl_id == kdm_cpl_id
    if cpl_match:
        log.info("CompositionPlaylistId matches")
    else:
        log.info(f"CPL ID mismatch: {cpl_id} vs. {kdm_cpl_id}")

    keys_match = True
    for k_id in kdm_key_ids:
        if k_id in cpl_key_ids:
            log.info(f"KeyId {k_id} found in CPL")
        else:
            log.info(f"KeyId {k_id} not found in CPL")
            keys_match = False

    return cpl_match and keys_match
