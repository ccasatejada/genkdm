import subprocess
import logging
import sys

from utils.utils import get_current_path

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="",
    datefmt='')

def main():
    try:
        result = subprocess.run(
            ['openssl', 'verify', '-CAfile',
             f"<(cat {get_current_path()}/files/tmp/intermediate_cert.pem {get_current_path()}/files/tmp/root_cert.pem)",
             f"{get_current_path()}/files/tmp/server_cert.pem"],
            capture_output=True,
            text=True,
            check=True
        )
        log.info(result.stdout)
    except subprocess.CalledProcessError as e:
        log.error(f"Error : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()