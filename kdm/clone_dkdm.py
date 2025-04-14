import base64
import uuid
import datetime
import subprocess
from pathlib import Path
from lxml import etree
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from utils.utils import get_current_path

# === CONFIGURATION ===
dkdm_path = Path(f"{get_current_path()}/files/dkdm/anydkdm.xml")
self_private_key_path = Path(f"{get_current_path()}/files/tmp/server_key.pem")
self_cert_chain_path = Path(f"{get_current_path()}/files/self/full_chain.pem")
target_cert_chain_path = Path(f"{get_current_path()}/files/certificate/certificate_chain.pem")
cpl_path = Path(f"{get_current_path()}/files/cpl/CPL_de1058f8-6db8-49c2-9259-87c35e313490.xml")
xsd_path = Path(f"{get_current_path()}/files/xsd/DCinemaSecurityMessage.xsd")
output_dir = Path(f"{get_current_path()}/files/output")
output_dir.mkdir(parents=True, exist_ok=True)

def decrypt_cek_from_dkdm(dkdm_path, private_key_path):
    with open(dkdm_path, "rb") as f:
        tree = etree.parse(f)
        root = tree.getroot()
        encrypted_cek_b64 = root.findtext(".//{*}CipherValue")
        encrypted_cek = base64.b64decode(encrypted_cek_b64)
        key_id = root.findtext(".//{*}KeyId").strip()
        cpl_id = root.findtext(".//{*}CompositionPlaylistId").strip()

    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

    cek = private_key.decrypt(
        encrypted_cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return cek, key_id, cpl_id


def encrypt_cek_for_target(cek, target_cert_path):
    with open(target_cert_path, "rb") as f:
        target_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
        target_public_key = target_cert.public_key()

    encrypted_cek = target_public_key.encrypt(
        cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    encrypted_cek_b64 = base64.b64encode(encrypted_cek).decode()
    return encrypted_cek_b64, target_cert


def generate_kdm_xml(cek_list, key_id, cpl_id, target_cert):
    now = datetime.datetime.utcnow()
    valid_from = now.isoformat() + "Z"
    valid_until = (now + datetime.timedelta(days=2)).isoformat() + "Z"
    content_title = "Re-KDM from DKDM"

    encrypted_track_blocks = ""
    typed_key_ids = ""

    for cek in cek_list:
        encrypted_cek_b64, _ = encrypt_cek_for_target(cek, target_cert_chain_path)
        encrypted_track_blocks += f"""
    <EncryptedTrackFile>
      <Id>{str(uuid.uuid4())}</Id>
      <KeyId>{key_id}</KeyId>
      <CipherData>
        <CipherValue>{encrypted_cek_b64}</CipherValue>
      </CipherData>
    </EncryptedTrackFile>"""

        typed_key_ids += f"""
        <TypedKeyId>
          <KeyId>{key_id}</KeyId>
          <KeyType>INGEST</KeyType>
        </TypedKeyId>"""

    kdm_template = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<DCinemaSecurityMessage xmlns=\"http://www.smpte-ra.org/schemas/430-1/2006/DS\">
  <AuthenticatedPublic xmlns=\"http://www.smpte-ra.org/schemas/430-1/2006/AKDM\">
    <MessageId>{str(uuid.uuid4())}</MessageId>
    <MessageType>http://www.smpte-ra.org/schemas/430-1/2006/KDM#</MessageType>
    <CompositionPlaylistId>{cpl_id}</CompositionPlaylistId>
    <ContentTitleText>{content_title}</ContentTitleText>
    <ContentKeysNotValidBefore>{valid_from}</ContentKeysNotValidBefore>
    <ContentKeysNotValidAfter>{valid_until}</ContentKeysNotValidAfter>
    <Signer>
      <X509SubjectName>{target_cert.subject.rfc4514_string()}</X509SubjectName>
      <X509IssuerName>{target_cert.issuer.rfc4514_string()}</X509IssuerName>
      <X509SerialNumber>{target_cert.serial_number}</X509SerialNumber>
    </Signer>
    <Recipient>
      <X509SubjectName>{target_cert.subject.rfc4514_string()}</X509SubjectName>
      <X509IssuerName>{target_cert.issuer.rfc4514_string()}</X509IssuerName>
      <X509SerialNumber>{target_cert.serial_number}</X509SerialNumber>
    </Recipient>
    <ContentKeys>
      <KeyIdList>{typed_key_ids}
      </KeyIdList>
    </ContentKeys>{encrypted_track_blocks}
  </AuthenticatedPublic>
</DCinemaSecurityMessage>
"""
    unsigned_kdm_path = output_dir / "kdm_to_target_unsigned.xml"
    with open(unsigned_kdm_path, "w", encoding="utf-8") as f:
        f.write(kdm_template)
    return unsigned_kdm_path


def sign_kdm(unsigned_path, signed_path):
    cmd = [
        "openssl", "cms", "-sign",
        "-in", str(unsigned_path),
        "-signer", str(self_cert_chain_path),
        "-inkey", str(self_private_key_path),
        "-outform", "DER",
        "-out", str(signed_path),
        "-nodetach", "-binary"
    ]
    subprocess.run(cmd, check=True)


def extract_xml_from_p7m(p7m_path, output_xml_path):
    cmd = [
        "openssl", "cms", "-verify",
        "-in", str(p7m_path),
        "-inform", "DER",
        "-noverify",
        "-nosigs",
        "-out", str(output_xml_path)
    ]
    subprocess.run(cmd, check=True)


def validate_with_xsd(xml_path, xsd_path):
    with open(xsd_path, 'rb') as f:
        xsd_doc = etree.parse(f)
        xsd_schema = etree.XMLSchema(xsd_doc)

    with open(xml_path, 'rb') as f:
        xml_doc = etree.parse(f)

    if xsd_schema.validate(xml_doc):
        print("[✅] XML KDM valide selon le XSD SMPTE.")
    else:
        print("[❌] Le XML ne valide pas le XSD.")
        for error in xsd_schema.error_log:
            print("  ↪️", error.message)


def check_kdm_vs_cpl(kdm_xml_path, cpl_path):
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
        kdm_key_ids = kdm_tree.findall(".//{*}KeyId")
        kdm_key_ids = [el.text for el in kdm_key_ids]

    print("[🔍] Vérification de la cohérence KDM / CPL...")
    if cpl_id == kdm_cpl_id:
        print("  ✅ CompositionPlaylistId concorde.")
    else:
        print(f"  ❌ CPL ID différent : {cpl_id} ≠ {kdm_cpl_id}")

    for k_id in kdm_key_ids:
        if k_id in cpl_key_ids:
            print(f"  ✅ KeyId {k_id} présent dans la CPL.")
        else:
            print(f"  ❌ KeyId {k_id} non trouvé dans la CPL.")


def main():
    cek, key_id, cpl_id = decrypt_cek_from_dkdm(dkdm_path, self_private_key_path)
    _, target_cert = encrypt_cek_for_target(cek, target_cert_chain_path)  # any for cert info
    unsigned_path = generate_kdm_xml([cek], key_id, cpl_id, target_cert)

    signed_path = output_dir / "kdm_to_target_signed.p7m"
    sign_kdm(unsigned_path, signed_path)

    extracted_xml_path = output_dir / "kdm_to_target_signed.xml"
    extract_xml_from_p7m(signed_path, extracted_xml_path)

    validate_with_xsd(extracted_xml_path, xsd_path)
    check_kdm_vs_cpl(extracted_xml_path, cpl_path)


if __name__ == "__main__":
    main()
