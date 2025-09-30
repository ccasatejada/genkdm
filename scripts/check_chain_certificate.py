import subprocess
import sys

from utils.logger import get_logger
from utils.utils import get_current_path

log = get_logger()

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