import argparse
import shlex
import subprocess
import sys
import logging

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="",
    datefmt='')

"""
    Utility script to check asn1 certificate thumbprint
    
    python get_certificate_thumbprint.py {path_to_pem_certificate}
    return -> Thumbprint certificate
"""

def get_cert_thumbprint(cert_file):
    try:
        # Extract ASN.1 data from certificate
        openssl_cmd = f'openssl asn1parse -in {cert_file} -out /tmp/test.tp -noout -strparse 4'
        subprocess.run(shlex.split(openssl_cmd), check=True, stdout=subprocess.PIPE)

        # SHA-1 computation
        openssl_cmd = 'openssl dgst -sha1 -binary /tmp/test.tp'
        cmd_1_process = subprocess.Popen(shlex.split(openssl_cmd), stdout=subprocess.PIPE)

        # Encoding to Base64
        openssl_cmd_2 = 'openssl base64'
        cert_thumb = subprocess.run(shlex.split(openssl_cmd_2), stdin=cmd_1_process.stdout, stdout=subprocess.PIPE,
                                    check=True)
        cmd_1_process.stdout.close()

        return cert_thumb.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        log.error(f"Error : {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Retrieve SHA-1 Base64 thumbprint from X.509 certificate.")
    parser.add_argument("cert_file", help="Path to PEM certificate")
    args = parser.parse_args()

    thumbprint = get_cert_thumbprint(args.cert_file)
    log.info(f"Thumbprint certificate : {thumbprint}")


if __name__ == "__main__":
    main()