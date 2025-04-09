import base64
import hashlib
import string

import pytest
from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459

from certificate.generate_self_signed_smpte import smpte_thumbprint, printable_dn
from utils.utils import get_current_path, verify_chain

# OID pour le rôle selon SMPTE
OID_ROLE = ObjectIdentifier("1.2.840.10070.8.1")

@pytest.fixture(scope="module")
def certs():
    """Charge les certificats générés par generate_certs()."""
    paths = {
        "root": f"{get_current_path(__file__)}/files/tmp/root_cert.pem",
        "intermediate": f"{get_current_path(__file__)}/files/tmp/intermediate_cert.pem",
        "leaf": f"{get_current_path(__file__)}/files/tmp/server_cert.pem",
    }
    loaded = {}
    for key, path in paths.items():
        with open(path, "rb") as f:
            loaded[key] = x509.load_pem_x509_certificate(f.read())
    return loaded

def fullchain_path():
    return f"{get_current_path(__file__)}/files/self/full_chain.pem"

def test_root_contains_authority_key_identifier():
    certs = get_cert_chain_from_pem(fullchain_path())
    root_cert = certs[-1]  # La racine est en dernier

    try:
        aki = root_cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    except x509.ExtensionNotFound:
        pytest.fail("Le certificat racine ne contient pas d'extension AuthorityKeyIdentifier (AKI)")

    assert aki is not None, "Extension AKI absente dans le certificat racine"

def test_dn_are_printablestring(certs):
    for name, cert in certs.items():
        for attr in cert.subject:
            # Vérifie qu'on a bien utilisé PrintableString pour CN, O et DN Qualifier
            if attr.oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, NameOID.DN_QUALIFIER):
                raw = cert.subject.public_bytes(serialization.Encoding.DER)
                decoded, _ = decoder.decode(raw, asn1Spec=rfc2459.Name())
                for rdn in decoded:
                    for attribute in rdn:
                        val = attribute['value']
                        assert isinstance(val, (rfc2459.PrintableString, rfc2459.DirectoryString)), \
                            f"{name}: Attribute {attr.oid} is not PrintableString: {type(val)}"

def test_thumbprint_is_subject_public_key(certs):
    for name, cert in certs.items():
        pubkey = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        decoded, _ = decoder.decode(pubkey, asn1Spec=rfc2459.SubjectPublicKeyInfo())
        bit_string = decoded.getComponentByName('subjectPublicKey').asOctets()
        thumb = base64.b64encode(hashlib.sha1(bit_string).digest()).decode()
        # Comparer le DN Qualifier au thumbprint
        dnq = cert.subject.get_attributes_for_oid(NameOID.DN_QUALIFIER)
        if dnq:
            assert dnq[0].value == thumb, f"{name}: DN Qualifier ≠ SMPTE thumbprint"

def test_role_extension(certs):
    roles_expected = {
        "root": "ROOT",
        "intermediate": "SIGNER",
        "leaf": "KDM_GENERATOR",
    }
    for name, cert in certs.items():
        ext = cert.extensions.get_extension_for_oid(OID_ROLE)
        role = ext.value.value.decode()
        assert role == roles_expected[name], f"{name}: rôle attendu {roles_expected[name]}, trouvé {role}"

def test_valid_basic_constraints(certs):
    assert certs["root"].extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert certs["intermediate"].extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert certs["leaf"].extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False

def test_chain_order():
    with open(fullchain_path(), "rb") as f:
        pem_data = f.read()

    certs = []
    for block in pem_data.split(b"-----END CERTIFICATE-----"):
        if b"-----BEGIN CERTIFICATE-----" in block:
            block += b"-----END CERTIFICATE-----\n"
            cert = x509.load_pem_x509_certificate(block)
            certs.append(cert)

    assert len(certs) == 3, f"full_chain.pem doit contenir 3 certificats, trouvé: {len(certs)}"

    leaf, intermediate, root = certs

    assert leaf.issuer == intermediate.subject, "Le certificat Leaf n'est pas émis par Intermediate"
    assert intermediate.issuer == root.subject, "Le certificat Intermediate n'est pas émis par Root"
    assert root.issuer == root.subject, "Le certificat Root devrait être auto-signé"

def test_serial_number_u64(certs):
    for name, cert in certs.items():
        assert cert.serial_number.bit_length() <= 64, f"{name}: serial > 64 bits"

# =====================================================================================================================


VALID_ROLES = {"ROOT", "SIGNER", "KDM_GENERATOR"}

def get_cert_chain_from_pem(pem_path):
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    certs = []
    for block in pem_data.split(b"-----END CERTIFICATE-----"):
        if b"-----BEGIN CERTIFICATE-----" in block:
            block += b"-----END CERTIFICATE-----\n"
            cert = x509.load_pem_x509_certificate(block)
            certs.append(cert)
    return certs

def test_certificate_roles():
    certs = get_cert_chain_from_pem(fullchain_path())
    assert len(certs) == 3, "La chaîne doit contenir exactement 3 certificats"

    for cert in certs:
        try:
            ext = cert.extensions.get_extension_for_oid(OID_ROLE)
        except x509.ExtensionNotFound:
            pytest.fail(f"Certificat sans extension rôle SMPTE (OID {OID_ROLE.dotted_string}) : {cert.subject}")

        role_raw = ext.value.value  # bytes
        try:
            role = role_raw.decode("ascii")
        except UnicodeDecodeError:
            pytest.fail(f"Le rôle SMPTE n'est pas encodé en ASCII : {role_raw}")

        assert role in VALID_ROLES, f"Rôle SMPTE invalide : {role} (attendus: {VALID_ROLES})"


# =====================================================================================================================

ROOT_CERT_PATH = f"{get_current_path()}/files/tmp/root_cert.pem"
INTERMEDIATE_CERT_PATH = f"{get_current_path()}/files/tmp/intermediate_cert.pem"
SERVER_CERT_PATH = f"{get_current_path()}/files/tmp/server_cert.pem"

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def test_certificate_chain():
    root_cert = load_cert(ROOT_CERT_PATH)
    intermediate_cert = load_cert(INTERMEDIATE_CERT_PATH)
    server_cert = load_cert(SERVER_CERT_PATH)

    assert intermediate_cert.issuer == root_cert.subject

    assert server_cert.issuer == intermediate_cert.subject

def test_extensions():
    root_cert = load_cert(ROOT_CERT_PATH)
    intermediate_cert = load_cert(INTERMEDIATE_CERT_PATH)
    server_cert = load_cert(SERVER_CERT_PATH)

    assert root_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert root_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True

    assert intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert intermediate_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True

    assert server_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert server_cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature is True

def test_smpte_thumbprint():
    root_cert = load_cert(ROOT_CERT_PATH)
    intermediate_cert = load_cert(INTERMEDIATE_CERT_PATH)
    server_cert = load_cert(SERVER_CERT_PATH)

    assert any(attr.oid == NameOID.DN_QUALIFIER for attr in root_cert.subject)
    assert any(attr.oid == NameOID.DN_QUALIFIER for attr in intermediate_cert.subject)
    assert any(attr.oid == NameOID.DN_QUALIFIER for attr in server_cert.subject)

    assert any(attr.oid == NameOID.DN_QUALIFIER for attr in root_cert.issuer)
    assert any(attr.oid == NameOID.DN_QUALIFIER for attr in intermediate_cert.issuer)
    assert any(attr.oid == NameOID.DN_QUALIFIER for attr in server_cert.issuer)

def test_printable_string():
    root_cert = load_cert(ROOT_CERT_PATH)
    intermediate_cert = load_cert(INTERMEDIATE_CERT_PATH)
    server_cert = load_cert(SERVER_CERT_PATH)

    for cert in [root_cert, intermediate_cert, server_cert]:
        for attribute in cert.subject:
            for v in attribute.value:
                assert v in string.printable
            assert attribute._type == _ASN1Type.PrintableString

def test_serial_number():
    root_cert = load_cert(ROOT_CERT_PATH)
    intermediate_cert = load_cert(INTERMEDIATE_CERT_PATH)
    server_cert = load_cert(SERVER_CERT_PATH)

    assert 0 <= root_cert.serial_number < 2**64
    assert 0 <= intermediate_cert.serial_number < 2**64
    assert 0 <= server_cert.serial_number < 2**64

# =====================================================================================================================

def get_role_from_cert(cert):
    for ext in cert.extensions:
        if ext.oid == OID_ROLE:
            return ext.value.value.decode('ascii')
    return None

def test_certificate_roles_smpte():
    root_cert = load_cert(ROOT_CERT_PATH)
    intermediate_cert = load_cert(INTERMEDIATE_CERT_PATH)
    server_cert = load_cert(SERVER_CERT_PATH)

    assert get_role_from_cert(root_cert) == "ROOT"
    assert get_role_from_cert(intermediate_cert) == "SIGNER"
    assert get_role_from_cert(server_cert) == "KDM_GENERATOR"

# ===================================================================================================================

def get_common_name_roles(cert):
    common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    roles = common_name.split('.')[0]
    return roles.split()

def test_certificate_roles_within_common_name():
    root_cert = load_cert(ROOT_CERT_PATH)
    intermediate_cert = load_cert(INTERMEDIATE_CERT_PATH)
    server_cert = load_cert(SERVER_CERT_PATH)

    assert len(get_common_name_roles(root_cert)) == 0
    assert len(get_common_name_roles(intermediate_cert)) == 0
    assert "signer" in get_common_name_roles(server_cert)

# ===================================================================================================================

def test_thumbprint():
    """Vérifie que le thumbprint est correctement calculé"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    thumbprint = smpte_thumbprint(private_key.public_key())

    assert thumbprint is not None
    assert isinstance(thumbprint, str)
    assert len(thumbprint) > 0


def test_dn_format():
    """Vérifie que les DN sont correctement formatés en PRINTABLESTRING"""
    dn = printable_dn("CommonName", "MyOrganization", "thumbprintExample")
    common_name = next((attr.value for attr in dn if attr.oid == NameOID.COMMON_NAME), None)

    assert common_name == "CommonName"
    assert all(isinstance(attr.value, str) for attr in dn)
    assert all(attr.value.isascii() for attr in dn)


def test_certificate_extensions():
    """Vérifie que les extensions sont présentes et conformes"""
    cert = load_pem_x509_certificate(open(fullchain_path(), "rb").read())

    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert key_usage is not None
    assert key_usage.value.digital_signature is True

    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic_constraints is not None
    assert basic_constraints.value.ca is False

    role_extension = cert.extensions.get_extension_for_oid(OID_ROLE)
    assert role_extension is not None
    assert role_extension.value.value == b"KDM_GENERATOR"


def test_certificate_chain():
    """ Root -> Intermediate -> Server """
    cert_chain = [open(ROOT_CERT_PATH, "rb").read(),
                  open(INTERMEDIATE_CERT_PATH, "rb").read(),
                  open(SERVER_CERT_PATH, "rb").read()]
    cert_chain_valid = verify_chain(cert_chain)

    assert cert_chain_valid is True
