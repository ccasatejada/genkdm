import argparse
import subprocess
import sys

from utils.logger import get_logger

log = get_logger()

"""
    Utility script to check asn1 certificate informations

    python get_certificate_thumbprint.py {path_to_pem_certificate}
    return -> certificate asn1 informations
"""


def parse_certificate(cert_file):
    try:
        result = subprocess.run(
            ['openssl', 'asn1parse', '-in', cert_file, '-inform', 'PEM'],
            capture_output=True,
            text=True,
            check=True
        )
        log.info(result.stdout)
    except subprocess.CalledProcessError as e:
        log.error(f"Error : {e}")
        sys.exit(1)



def main():
    parser = argparse.ArgumentParser(description="Retrieve SHA-1 Base64 thumbprint from X.509 certificate.")
    parser.add_argument("cert_file", help="Path to PEM certificate")
    args = parser.parse_args()

    parse_certificate(args.cert_file)


if __name__ == "__main__":
    main()