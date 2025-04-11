import base64
import hashlib
import locale
import logging
import os
import sys
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import UnrecognizedExtension
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459

from utils.utils import get_current_path

"""
    Main script
    It permits to generate self signed certificate for the server/device itself.
    It conforms to SMPTE ST 430-2 documentation:
        - PEM Cert chain
        - With sha1 thumbprint encoded with base64 (asn1 compliance) -> see get_certificate_thumbprint.py
        - all certificates (root>intermediate>server) have the correct extensions
        - qualifier thumbprint is TBS (To Be Signed)/SubjectPublicKey workaround described by the specification
        - serial number must not be above u64 (64-bit unsigned integer type)
        - string must be PRINTABLESTRING and not UTF8STRING -> see parse_pem_certificate.py
    With the public certificate chain -> it allows DCP (digital cinema package) maker (postprod, labs etc) to make DKDM (master Key delivery message)
    to our server.
    With the private key -> we will able to "duplicate" master kdm, make it and signed it to a target certificate, 
    (the device that will runs DCP (through theatrical management system (TMS) that ingest the newly created kdm)).
"""

os.environ['LC_ALL'] = 'C'
locale.setlocale(locale.LC_ALL, 'C')

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="",
    datefmt='')

class ScriptException(Exception):
    def __init__(self):
        pass


def get_oid_device_role():
    # SMPTE-specific OID for role for device
    return ObjectIdentifier("1.2.840.10070.8.1")

def get_oid_role():
    # SMPTE-specific OID role for every certs
    return ObjectIdentifier("1.2.840.10008.3.1.1.1")

def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def smpte_thumbprint(pubkey):
    spki = pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Decode SubjectPublicKeyInfo to obtain BIT STRING
    spki_decoded, _ = decoder.decode(spki, asn1Spec=rfc2459.SubjectPublicKeyInfo())
    bit_string = spki_decoded.getComponentByName('subjectPublicKey')

    # Get BIT STRING's octets and exclude non-used bits
    bit_string_bytes = bit_string.asOctets()

    # Compute SHA-1 from BIT STRING
    sha1_digest = hashlib.sha1(bit_string_bytes).digest()

    # Encode to Base64
    return base64.b64encode(sha1_digest).decode('ascii')

def printable_dn(cn, org, dn_qualifier):
    attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn, _type=_ASN1Type.PrintableString),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org, _type=_ASN1Type.PrintableString),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org, _type=_ASN1Type.PrintableString),
        x509.NameAttribute(NameOID.DN_QUALIFIER, dn_qualifier, _type=_ASN1Type.PrintableString)
    ]
    return x509.Name(attrs)

def build_cert(subject, issuer, pubkey, issuer_key, is_ca, validity_days, role, issuer_aki=None, length=None):
    now = datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pubkey)
        .serial_number(x509.random_serial_number() & (2**64 - 1))  # SMPTE: must fit in uint64
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=length), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=not is_ca,
            key_encipherment=not is_ca,
            content_commitment=False,
            data_encipherment=not is_ca,
            key_agreement=False,
            key_cert_sign=is_ca,
            crl_sign=is_ca,
            encipher_only=False,
            decipher_only=False,
        ), critical=False)
    )

    # Authority Key Identifier (from issuer)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=issuer_aki.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None),
        critical=False,
    )

    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey), critical=False)
    builder = builder.add_extension(
        UnrecognizedExtension(
            get_oid_role(),
            b"signer" if is_ca else b"device"
        ),
        critical=False
    )
    if not is_ca:
        # Extension SMPTE: Role
        builder = builder.add_extension(
            x509.UnrecognizedExtension(get_oid_device_role(), role.encode("ascii")),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([]), critical=False
        )

    return builder.sign(issuer_key, hashes.SHA256())

def write_cert_and_key(path_prefix, cert, key):
    with open(path_prefix + "_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(path_prefix + "_key.pem", "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

def write_chain(filename, certs):
    with open(filename, "wb") as f:
        for c in certs:
            f.write(c.public_bytes(serialization.Encoding.PEM))


def generate_certs(nb_year):
    years = 365 * nb_year
    years_ca = years + 365

    # 1. Root
    root_key = gen_key()
    root_thumb = smpte_thumbprint(root_key.public_key())
    root_dn = printable_dn(".RootCA-KDMGENORG", "KDMGENSelfSigned", root_thumb)
    root_cert = build_cert(
        subject=root_dn,
        issuer=root_dn,
        pubkey=root_key.public_key(),
        issuer_key=root_key,
        is_ca=True,
        validity_days=years_ca,
        role="ROOT",
        issuer_aki=x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
        # issuer_aki=None,
        length=3
    )
    write_cert_and_key(f"{get_current_path()}/files/tmp/root", root_cert, root_key)

    # 2. Intermediate
    inter_key = gen_key()
    inter_thumb = smpte_thumbprint(inter_key.public_key())
    inter_dn = printable_dn(".SignerCA-KDMGENORG", "KDMGENSelfSigned", inter_thumb)
    inter_cert = build_cert(
        subject=inter_dn,
        issuer=root_cert.subject,
        pubkey=inter_key.public_key(),
        issuer_key=root_key,
        is_ca=True,
        validity_days=years_ca,
        role="SIGNER",
        issuer_aki=root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
        length=2
    )
    write_cert_and_key(f"{get_current_path()}/files/tmp/intermediate", inter_cert, inter_key)

    # 3. Server (Leaf)
    leaf_key = gen_key()
    leaf_thumb = smpte_thumbprint(leaf_key.public_key())
    leaf_dn = printable_dn("signer.kdmtool.KDMGENORG", "KDMGENSelfSigned", leaf_thumb)
    leaf_cert = build_cert(
        subject=leaf_dn,
        issuer=inter_cert.subject,
        pubkey=leaf_key.public_key(),
        issuer_key=inter_key,
        is_ca=False,
        validity_days=years,
        role="KDM_GENERATOR",
        issuer_aki=inter_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value,
    )
    write_cert_and_key(f"{get_current_path()}/files/tmp/server", leaf_cert, leaf_key)

    # 4. Export chain
    write_chain(f"{get_current_path()}/files/self/full_chain.pem", [leaf_cert, inter_cert, root_cert])
    log.info(f"Chain certificate SMPTE/430-2 generated : {get_current_path()}/files/self/full_chain.pem")


PARAMETER_ERROR = 'parameter --year (-y) is mandatory - i.e. --year=10 or -y 10'
if __name__ == '__main__':
    arguments = sys.argv[1:]

    if len(arguments) == 0:
        log.info(PARAMETER_ERROR)
        raise ScriptException()
    else:
        one_opt = arguments[0]
        key_and_value = None
        if '--year=' in one_opt:
            key_and_value = one_opt.split('=')
        elif '-y ' in one_opt:
            key_and_value = one_opt.split(' ')

        if key_and_value is None or len(key_and_value) != 2:
            log.error(PARAMETER_ERROR)
            raise ScriptException()

        try:
            year_length = int(key_and_value[1])
        except ValueError as e:
            log.error(e)
            raise ScriptException()

        try:
            generate_certs(year_length)
        except ScriptException:
            pass