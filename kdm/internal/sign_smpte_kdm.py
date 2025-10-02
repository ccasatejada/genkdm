"""
SMPTE-compliant KDM signing according to ST 430-3 specifications.

This module implements XML digital signatures for KDMs according to:
- SMPTE ST 430-3: D-Cinema Operations - Generic Extra-Theater Message Format
- SMPTE ST 430-2: D-Cinema Operations - Digital Certificate
- W3C XML Digital Signature standard
"""
from datetime import datetime

from signxml import XMLSigner, methods
from lxml import etree
from pathlib import Path

from utils.utils import get_current_path


def sign_smpte_kdm(kdm_file_path, output_file_path=None, signer_key_path=None, signer_cert_path=None):
    """
    Sign a KDM according to SMPTE ST 430-3 specifications.

    Args:
        kdm_file_path (str): Path to unsigned KDM XML file
        output_file_path (str, optional): Path for signed KDM. Defaults to kdm_file_signed.xml
        signer_key_path (str, optional): Path to signer private key. Defaults to server_key.pem
        signer_cert_path (str, optional): Path to signer certificate. Defaults to server_cert.pem

    Returns:
        str: Path to signed KDM file

    Raises:
        FileNotFoundError: If KDM file or certificates not found
        ValueError: If KDM structure is invalid for SMPTE signing
    """

    # Set default paths
    if output_file_path is None:
        kdm_path = Path(kdm_file_path)
        output_file_path = kdm_path.parent / f"{kdm_path.stem}_signed.xml"

    if signer_key_path is None:
        signer_key_path = f"{get_current_path()}/files/self/server_key.pem"

    if signer_cert_path is None:
        signer_cert_path = f"{get_current_path()}/files/self/server_cert.pem"

    # Validate input files exist
    for file_path in [kdm_file_path, signer_key_path, signer_cert_path]:
        if not Path(file_path).exists():
            raise FileNotFoundError(f"Required file not found: {file_path}")

    # Load and parse KDM XML
    with open(kdm_file_path, "rb") as f:
        xml_doc = etree.parse(f)
        root = xml_doc.getroot()

    # Validate KDM structure for SMPTE compliance
    if not _validate_kdm_structure(root):
        raise ValueError("KDM structure is not SMPTE ST 430-3 compliant")

    # Configure SMPTE-compliant XML signer
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",  # SMPTE ST 430-3 requirement
        digest_algorithm="sha256",         # SMPTE ST 430-3 requirement
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"  # Canonical XML
    )

    # Load signer credentials
    with open(signer_key_path, "rb") as key_file:
        private_key = key_file.read()

    with open(signer_cert_path, "rb") as cert_file:
        certificate = cert_file.read()

    # Sign the KDM with SMPTE-specific parameters
    signed_root = signer.sign(
        xml_doc,
        key=private_key,
        cert=certificate
    )

    # Save signed KDM
    with open(output_file_path, "wb") as f:
        f.write(etree.tostring(
            signed_root,
            pretty_print=True,
            xml_declaration=True,
            encoding="UTF-8"
        ))

    print(f"SMPTE-compliant KDM signed: {output_file_path}")
    return str(output_file_path)


def _validate_kdm_structure(root):
    """
    Validate KDM XML structure for SMPTE ST 430-3 compliance.

    Args:
        root: XML root element

    Returns:
        bool: True if structure is valid for signing
    """
    # Check root namespace
    expected_ns = "http://www.smpte-ra.org/schemas/430-3/2006/ETM"
    if root.nsmap.get(None) != expected_ns:
        print(f"Invalid root namespace. Expected {expected_ns}, got {root.nsmap.get(None)}")
        return False

    # Check for required ETM elements
    auth_public = root.find(".//{http://www.smpte-ra.org/schemas/430-3/2006/ETM}AuthenticatedPublic")
    if auth_public is None:
        print("Missing AuthenticatedPublic element")
        return False

    auth_private = root.find(".//{http://www.smpte-ra.org/schemas/430-3/2006/ETM}AuthenticatedPrivate")
    if auth_private is None:
        print("Missing AuthenticatedPrivate element")
        return False

    # Check for KDM required extensions
    kdm_req_ext = root.find(".//{http://www.smpte-ra.org/schemas/430-1/2006/KDM}KDMRequiredExtensions")
    if kdm_req_ext is None:
        print("Missing KDMRequiredExtensions element")
        return False

    print("KDM structure validated for SMPTE signing")
    return True


def _get_signature_insert_index(root):
    """
    Determine where to insert signature according to SMPTE ST 430-3.

    Per SMPTE ST 430-3, signature should be placed after AuthenticatedPrivate.

    Args:
        root: XML root element

    Returns:
        int: Index where signature should be inserted
    """
    auth_private = root.find(".//{http://www.smpte-ra.org/schemas/430-3/2006/ETM}AuthenticatedPrivate")
    if auth_private is not None:
        # Insert signature after AuthenticatedPrivate
        return list(root).index(auth_private) + 1

    # Fallback: insert at end
    return len(list(root))


def sign_generated_kdm(kdm_path_from_generator):
    """
    Convenience function to sign a KDM generated by clone_dkdm_to_kdm.

    Args:
        kdm_path_from_generator: Path returned from KDMGenerator.generate_kdm()

    Returns:
        str: Path to signed KDM file
    """
    return sign_smpte_kdm(kdm_path_from_generator)


def verify_smpte_signature(signed_kdm_path, ca_cert_path=None):
    """
    Verify SMPTE-compliant KDM signature (basic verification).

    Args:
        signed_kdm_path (str): Path to signed KDM
        ca_cert_path (str, optional): Path to CA certificate for chain validation

    Returns:
        bool: True if signature is valid
    """
    from signxml import XMLVerifier

    try:
        with open(signed_kdm_path, "rb") as f:
            signed_xml = f.read()

        verifier = XMLVerifier()

        if ca_cert_path:
            with open(ca_cert_path, "rb") as ca_file:
                ca_cert = ca_file.read()
            verified_data = verifier.verify(signed_xml, ca_cert=ca_cert)
        else:
            verified_data = verifier.verify(signed_xml)

        print("KDM signature verification successful")
        return True

    except Exception as e:
        print(f"KDM signature verification failed: {e}")
        return False


if __name__ == "__main__":
    # Example usage - avoid circular import
    print("Use this module by importing sign_smpte_kdm function")
    print("Example:")
    print("from utils.sign_smpte_kdm import sign_smpte_kdm")
    print("signed_path = sign_smpte_kdm('path/to/kdm.xml')")