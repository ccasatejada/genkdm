import re

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

def get_current_path(curfile=__file__):
    _path = curfile.split('/')[:-1]
    _path = _path[:-1]
    return '/'.join(_path)


def verify_chain(cert_chain):
    try:
        # Charger les certificats de la chaîne
        certs = [load_pem_x509_certificate(cert, default_backend()) for cert in cert_chain]

        # Vérifier que la chaîne est valide (Root -> Intermediate -> Server)
        for i in range(1, len(certs)):
            certs[i].issuer == certs[i - 1].subject  # Le certificat i doit être signé par le certificat i-1

        return True
    except Exception as e:
        return False