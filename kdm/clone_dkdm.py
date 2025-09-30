from datetime import datetime

from kdm.internal.kdm_generator import KDMGenerator
from kdm.internal.kdm_validator import validate_kdm_xml, check_kdm_against_cpl
from kdm.internal.sign_smpte_kdm import sign_smpte_kdm
from utils.logger import get_logger
from utils.utils import get_current_path

log = get_logger()


def clone_dkdm_to_kdm(start_datetime, end_datetime):
    # Paths configuration
    server_private_key = f"{get_current_path()}/files/tmp/server_key.pem"
    server_cert = f"{get_current_path()}/files/self/full_chain.pem"
    dkdm_file = f"{get_current_path()}/files/dkdm/kdm_Test_des_equipements_de_projection_VO_Varietes_Les_Melun_4_110425_110426.xml"
    target_cert_file = f"{get_current_path()}/files/certificate/certificate_chain.pem"
    cpl_file = f"{get_current_path()}/files/cpl/CPL_de1058f8-6db8-49c2-9259-87c35e313490.xml"
    xsd_file = f"{get_current_path()}/files/xsd/DCinemaSecurityMessage.xsd"

    # Create KDM generator
    kdm_gen = KDMGenerator(server_private_key, server_cert)

    # Generate KDM
    kdm_path, kdm_xml = kdm_gen.generate_kdm(
        dkdm_file, target_cert_file,
        start_datetime, end_datetime,
        "Test KDM from DKDM"
    )

    log.info(f"KDM generated: {kdm_path}")

    # Validate against XSD
    validate_kdm_xml(kdm_path, xsd_file)
    # Check against CPL
    check_kdm_against_cpl(kdm_path, cpl_file)

    return kdm_path


def clone_dkdm_to_kdm_signed(start_datetime, end_datetime):
    """
    Generate and sign a KDM according to SMPTE ST 430-3 specifications.

    Returns:
        str: Path to signed KDM file
    """
    # Generate unsigned KDM
    unsigned_kdm_path = clone_dkdm_to_kdm(start_datetime, end_datetime)

    # Sign the KDM according to SMPTE ST 430-3
    try:
        signed_kdm_path = sign_smpte_kdm(unsigned_kdm_path)
        log.info(f"KDM signed according to SMPTE ST 430-3: {signed_kdm_path}")
        return signed_kdm_path
    except Exception as e:
        log.error(f"Failed to sign KDM: {e} - unsigned kdm here : {unsigned_kdm_path}")
        return unsigned_kdm_path


if __name__ == "__main__":
    # Example
    clone_dkdm_to_kdm(
        start_datetime=datetime(2024, 11, 4, 10, 0, 0),
        end_datetime=datetime(2024, 11, 6, 23, 59, 59)
    )