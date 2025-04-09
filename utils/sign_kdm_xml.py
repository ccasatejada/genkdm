from signxml import XMLSigner, methods
from lxml import etree

from utils.utils import get_current_path


def sign(kdm_file):
    signed_kdm_file = kdm_file.replace('.xml', '_signed.xml')

    with open(kdm_file, "rb") as f:
        xml_data = etree.parse(f)

    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256"
    )

    # Charger clé + cert
    with open(f"{get_current_path()}/files/self/server_key.pem", "rb") as key_file:
        key_data = key_file.read()

    with open(f"{get_current_path()}/files/self/server_cert.pem", "rb") as cert_file:
        cert_data = cert_file.read()

    signed_root = signer.sign(
        xml_data,
        key=key_data,
        cert=cert_data,
        reference_uri="",
    )

    # Écrire le XML signé
    with open(signed_kdm_file, "wb") as f:
        f.write(etree.tostring(signed_root, pretty_print=True, xml_declaration=True, encoding="UTF-8"))

    print(f"KDM signé : {signed_kdm_file}")