import argparse
import shlex
import subprocess
import sys

def get_cert_thumbprint(cert_file):
    """ Récupère l'empreinte du certificat """
    try:
        # Extraction des données ASN.1 du certificat
        openssl_cmd = f'openssl asn1parse -in {cert_file} -out /tmp/test.tp -noout -strparse 4'
        subprocess.run(shlex.split(openssl_cmd), check=True, stdout=subprocess.PIPE)

        # Calcul du SHA-1
        openssl_cmd = 'openssl dgst -sha1 -binary /tmp/test.tp'
        cmd_1_process = subprocess.Popen(shlex.split(openssl_cmd), stdout=subprocess.PIPE)

        # Encodage en Base64
        openssl_cmd_2 = 'openssl base64'
        cert_thumb = subprocess.run(shlex.split(openssl_cmd_2), stdin=cmd_1_process.stdout, stdout=subprocess.PIPE,
                                    check=True)
        cmd_1_process.stdout.close()

        return cert_thumb.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du traitement du certificat : {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Récupère l'empreinte SHA-1 Base64 d'un certificat X.509.")
    parser.add_argument("cert_file", help="Chemin du fichier certificat au format PEM")
    args = parser.parse_args()

    thumbprint = get_cert_thumbprint(args.cert_file)
    print(f"Empreinte du certificat : {thumbprint}")


if __name__ == "__main__":
    main()