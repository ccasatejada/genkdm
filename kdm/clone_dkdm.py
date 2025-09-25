from datetime import datetime

from kdm.internal.kdm_generator import KDMGenerator
from kdm.internal.kdm_validator import validate_kdm_xml, check_kdm_against_cpl
from utils.utils import get_current_path


def clone_dkdm_to_kdm():
    # Paths configuration
    server_private_key = f"{get_current_path()}/files/tmp/server_key.pem"
    server_cert = f"{get_current_path()}/files/self/full_chain.pem"
    dkdm_file = f"{get_current_path()}/files/dkdm/kdm_Test_des_equipements_de_projection_VO_Varietes_Les_Melun_4_110425_110426.xml"
    target_cert_file = f"{get_current_path()}/files/certificate/certificate_chain.pem"
    cpl_file = f"{get_current_path()}/files/cpl/CPL_de1058f8-6db8-49c2-9259-87c35e313490.xml"
    xsd_file = f"{get_current_path()}/files/xsd/DCinemaSecurityMessage.xsd"

    # Create KDM generator
    kdm_gen = KDMGenerator(server_private_key, server_cert)

    # Set validity period
    start_time = datetime(2024, 11, 4, 10, 0, 0)  # Nov 4, 2024, 10:00 AM
    end_time = datetime(2024, 11, 6, 23, 59, 59)    # Nov 6, 2024, 11:59 PM

    # Generate KDM
    kdm_path, kdm_xml = kdm_gen.generate_kdm(
        dkdm_file, target_cert_file,
        start_time, end_time,
        "Test KDM from DKDM"
    )

    print(f"[\u2705] KDM generated: {kdm_path}")

    # Validate against XSD
    validate_kdm_xml(kdm_path, xsd_file)
    # Check against CPL
    check_kdm_against_cpl(kdm_path, cpl_file)

    return kdm_path


if __name__ == "__main__":
    clone_dkdm_to_kdm()