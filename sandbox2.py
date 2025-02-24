from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from lxml import etree
from base64 import b64encode
from datetime import datetime, timedelta, timezone
import argparse
import os
import xml.etree.ElementTree as ET


def load_certificate(cert_path):
    with open(cert_path, 'rb') as f:
        return RSA.import_key(f.read())


def parse_cpl_uuid_and_title(cpl_path):
    tree = ET.parse(cpl_path)
    root = tree.getroot()
    uuid_element = root.find(".//{*}Id")
    title_element = root.find(".//{*}ContentTitleText")

    cpl_uuid = uuid_element.text[9:] if uuid_element is not None and uuid_element.text.startswith("urn:uuid:") else None
    content_title_text = title_element.text if title_element is not None else None

    return cpl_uuid, content_title_text


def load_dkdm(dkdm_folder, cpl_uuid):
    for file in os.listdir(dkdm_folder):
        if file.endswith(".xml"):
            dkdm_path = os.path.join(dkdm_folder, file)
            tree = ET.parse(dkdm_path)
            root = tree.getroot()
            uuid_element = root.find(".//{*}CompositionPlaylistId")
            if uuid_element is not None and uuid_element.text.startswith("urn:uuid:") and uuid_element.text[
                                                                                          9:] == cpl_uuid:
                return etree.parse(dkdm_path).getroot()
    return None


def generate_kdm(issuer_cert_path, recipient_cert_path, dkdm_folder, cpl_path):
    key_issuer = load_certificate(issuer_cert_path)
    key_recipient = load_certificate(recipient_cert_path)

    cpl_uuid, content_title_text = parse_cpl_uuid_and_title(cpl_path)
    if cpl_uuid is None:
        raise ValueError("Invalid CPL file: UUID not found")
    if content_title_text is None:
        raise ValueError("Invalid CPL file: ContentTitleText not found")

    dkdm_xml = load_dkdm(dkdm_folder, cpl_uuid)
    if dkdm_xml is None:
        raise FileNotFoundError(f"No DKDM found for CPL UUID: {cpl_uuid}")

    composition_playlist_id = f'urn:uuid:{cpl_uuid}'

    content_keys_not_valid_before = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat() + "Z"
    content_keys_not_valid_after = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat() + "Z"

    kdm_xml = etree.Element("DCinemaSecurityMessage", nsmap={
        None: "http://www.smpte-ra.org/schemas/430-3/2006/ETM",
        "dsig": "http://www.w3.org/2000/09/xmldsig#",
        "enc": "http://www.w3.org/2001/04/xmlenc#"
    })

    authenticated_public = etree.SubElement(kdm_xml, "AuthenticatedPublic", Id="ID_AuthenticatedPublic")
    etree.SubElement(authenticated_public, "MessageId").text = f"urn:uuid:{os.urandom(16).hex()}"
    etree.SubElement(authenticated_public, "MessageType").text = "http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type"
    etree.SubElement(authenticated_public, "AnnotationText").text = content_title_text
    etree.SubElement(authenticated_public, "IssueDate").text = datetime.now(timezone.utc).isoformat() + "Z"

    kdm_required_extensions = etree.SubElement(etree.SubElement(authenticated_public, "RequiredExtensions"),
                                               "KDMRequiredExtensions")

    etree.SubElement(kdm_required_extensions, "CompositionPlaylistId").text = composition_playlist_id
    etree.SubElement(kdm_required_extensions, "ContentTitleText").text = content_title_text
    etree.SubElement(kdm_required_extensions, "ContentKeysNotValidBefore").text = content_keys_not_valid_before
    etree.SubElement(kdm_required_extensions, "ContentKeysNotValidAfter").text = content_keys_not_valid_after

    key_id_list = etree.SubElement(kdm_required_extensions, "KeyIdList")

    for key_id in dkdm_xml.findall(".//KeyIdList/TypedKeyId"):
        key_type = key_id.find("KeyType").text
        key_value = key_id.find("KeyId").text
        typed_key_id = etree.SubElement(key_id_list, "TypedKeyId")
        etree.SubElement(typed_key_id, "KeyType").text = key_type
        etree.SubElement(typed_key_id, "KeyId").text = key_value

    authenticated_private = etree.SubElement(kdm_xml, "AuthenticatedPrivate", Id="ID_AuthenticatedPrivate")

    for key_id in dkdm_xml.findall(".//KeyIdList/TypedKeyId"):
        encrypted_key = etree.SubElement(authenticated_private, etree.QName(kdm_xml.nsmap['enc'], "EncryptedKey"))

        cipher_rsa = PKCS1_OAEP.new(key_recipient.publickey())
        content_key = get_random_bytes(16)
        encrypted_content_key = cipher_rsa.encrypt(content_key)

        etree.SubElement(encrypted_key, etree.QName(kdm_xml.nsmap['enc'], "CipherData")).text = b64encode(
            encrypted_content_key).decode('utf-8')

    signature = etree.SubElement(kdm_xml, etree.QName(kdm_xml.nsmap['dsig'], "Signature"))
    signed_info = etree.SubElement(signature, etree.QName(kdm_xml.nsmap['dsig'], "SignedInfo"))

    etree.SubElement(signed_info, etree.QName(kdm_xml.nsmap['dsig'], "CanonicalizationMethod"),
                     Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")
    etree.SubElement(signed_info, etree.QName(kdm_xml.nsmap['dsig'], "SignatureMethod"),
                     Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

    signature_value = pkcs1_15.new(key_issuer).sign(SHA256.new(etree.tostring(signed_info)))
    etree.SubElement(signature, etree.QName(kdm_xml.nsmap['dsig'], "SignatureValue")).text = b64encode(
        signature_value).decode('utf-8')

    return etree.tostring(kdm_xml, pretty_print=True).decode('utf-8')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate KDM from DKDM")
    parser.add_argument("--issuer", required=True, help="Path to issuer certificate .pem")
    parser.add_argument("--recipient", required=True, help="Path to recipient certificate .pem")
    parser.add_argument("--dkdm_folder", required=True, help="Path to DKDM folder")
    parser.add_argument("--cpl", required=True, help="Path to CPL file")

    args = parser.parse_args()
    kdm_xml = generate_kdm(args.issuer, args.recipient, args.dkdm_folder, args.cpl)
    print(kdm_xml)
