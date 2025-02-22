import base64
import hashlib
import locale
import logging
import os
import sys
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
from OpenSSL import crypto
from OpenSSL.crypto import PKey

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


def calculate_smpte_thumbprint(cert):
    """Calcule le thumbprint conforme à SMPTE 430-2 (SHA-1 + Base64)."""
    # Extraire le SubjectPublicKeyInfo
    spki = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())

    # Décoder le SubjectPublicKeyInfo pour obtenir le BIT STRING
    spki_decoded, _ = decoder.decode(spki, asn1Spec=rfc2459.SubjectPublicKeyInfo())
    bit_string = spki_decoded.getComponentByName('subjectPublicKey')

    # Obtenir les octets du BIT STRING en excluant les bits non utilisés
    bit_string_bytes = bit_string.asOctets()

    # Calculer le SHA-1 du BIT STRING
    sha1_digest = hashlib.sha1(bit_string_bytes).digest()

    # Encoder en Base64
    return base64.b64encode(sha1_digest).decode('ascii')

# Fonction pour créer un certificat
def create_certificate(subject_name, issuer_name, public_key, private_key, ca=False, path_length=None, key_usage=None, issuer_qualifier=None):
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(int.from_bytes(os.urandom(8), byteorder="big") & (2 ** 64 - 1))
    for c in subject_name.get_components():
        cert.get_subject().__setattr__(c[0].decode('ascii'), c[1].decode('ascii'))
    for c in issuer_name.get_components():
        cert.get_issuer().__setattr__(c[0].decode('ascii'), c[1].decode('ascii'))

    cert.set_pubkey(PKey.from_cryptography_key(public_key))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(3650 * 24 * 60 * 60 if ca else 365 * 24 * 60 * 60)

    # Extensions
    if ca:
        basic_constraints = "CA:TRUE"
        if path_length is not None:
            basic_constraints += ", pathlen:%d" % path_length
    else:
        basic_constraints = "CA:FALSE"

    cert.add_extensions([
        crypto.X509Extension(b'basicConstraints', False, basic_constraints.encode())
    ])

    if key_usage:
        _usages = ', '.join([k for k, v in key_usage.items() if v]).encode()
        cert.add_extensions([
            crypto.X509Extension(b'keyUsage', False, _usages)
        ])

    cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
    ])

    # Ajouter authorityKeyIdentifier
    cert.add_extensions([
        crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=cert)
    ])

    cert.sign(private_key, 'sha256')

    dn_qualifier = calculate_smpte_thumbprint(cert)
    cert.get_subject().__setattr__('dnQualifier', dn_qualifier)

    if issuer_qualifier is None:
        # root cert
        cert.get_issuer().__setattr__('dnQualifier', dn_qualifier)
    else:
        cert.get_issuer().__setattr__('dnQualifier', issuer_qualifier)

    return cert, dn_qualifier

# Fonction pour générer une clé RSA
def generate_rsa_key():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    return key

# Fonction pour créer un X509 Name avec des PrintableString
def create_x509_name(common_name, organization):
    name = crypto.X509Name(crypto.X509().get_subject())
    name.__setattr__("CN", value=common_name.decode('ascii'))
    name.__setattr__("O", value=organization.decode('ascii'))
    return name

# Générer la clé privée pour le certificat racine
private_key_root = generate_rsa_key()
public_key_root = private_key_root.to_cryptography_key().public_key()

root_subject = create_x509_name(b"RootCA", b"RootOrganization")

certificate_root, dn_qualifier_root = create_certificate(
    subject_name=root_subject,
    issuer_name=root_subject,
    public_key=public_key_root,
    private_key=private_key_root,
    ca=True,
    key_usage={"keyCertSign": True}
)

# Générer la clé privée pour le certificat intermédiaire
private_key_intermediate = generate_rsa_key()
public_key_intermediate = private_key_intermediate.to_cryptography_key().public_key()

intermediate_subject = create_x509_name(b"IntermediateCA", b"IntermediateOrganization")

certificate_intermediate, dn_qualifier_intermediate = create_certificate(
    subject_name=intermediate_subject,
    issuer_name=root_subject,
    public_key=public_key_intermediate,
    private_key=private_key_root,
    ca=True,
    key_usage={"keyCertSign": True, "cRLSign": True},
    issuer_qualifier=dn_qualifier_root
)

# Générer la clé privée pour le certificat serveur
private_key_server = generate_rsa_key()
public_key_server = private_key_server.to_cryptography_key().public_key()

server_subject = create_x509_name(b"ServerCert", b"ServerOrganization")

certificate_server, dn_qualifier_server = create_certificate(
    subject_name=server_subject,
    issuer_name=intermediate_subject,
    public_key=public_key_server,
    private_key=private_key_intermediate,
    ca=False,
    key_usage={"digitalSignature": True, "keyEncipherment": True, "dataEncipherment": True},
    issuer_qualifier=dn_qualifier_intermediate
)

# Sauvegarde des certificats et clés
with open("cert_chain.pem", "wb") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate_root))
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate_intermediate))
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate_server))

with open("server_key.pem", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key_server))

print("Chaîne de certificats et clé privée générées avec succès.")


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
            log.info(PARAMETER_ERROR)
            raise ScriptException()

        try:
            year_length = int(key_and_value[1])
        except ValueError as e:
            log.info(e)
            raise ScriptException

    print(arguments)
    log.info('Fin du programme')
