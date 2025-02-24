from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from lxml import etree
from base64 import b64encode
from datetime import datetime, timedelta, timezone

uuid_prefix = 'urn:uuid:'

# Générer des paires de clés RSA pour l'émetteur et le destinataire
key_issuer = RSA.generate(2048)
key_recipient = RSA.generate(2048)

# Informations sur le KDM
composition_playlist_id = '{}{}'.format(uuid_prefix, 'ccf2633d-cc6a-4deb-b450-23c1524f042c')
content_title_text = "Pachamama_FTR-1_F_FR-XX_FR_51-VI_2K_FOLI_20181113_HVY_IOP_OV"
content_keys_not_valid_before = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat() + "Z"
content_keys_not_valid_after = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat() + "Z"

# Créer le contenu XML du KDM
kdm_xml = etree.Element("DCinemaSecurityMessage",
                        nsmap={None: "http://www.smpte-ra.org/schemas/430-3/2006/ETM",
                               "dsig": "http://www.w3.org/2000/09/xmldsig#",
                               "enc": "http://www.w3.org/2001/04/xmlenc#"})

authenticated_public = etree.SubElement(kdm_xml, "AuthenticatedPublic", Id="ID_AuthenticatedPublic")
etree.SubElement(authenticated_public, "MessageId").text = "urn:uuid:08bca137-79fb-4711-85fc-725a1e8f8b65"
etree.SubElement(authenticated_public, "MessageType").text = "http://www.smpte-ra.org/430-1/2006/KDM#kdm-key-type"
etree.SubElement(authenticated_public, "AnnotationText").text = content_title_text + " ~ KDM for LE SPB MD FM SM.IMB-228398.DC.DOLPHIN.DC2.SMPTE"
etree.SubElement(authenticated_public, "IssueDate").text = datetime.now(timezone.utc).isoformat() + "Z"

signer = etree.SubElement(authenticated_public, "Signer")
etree.SubElement(signer, etree.QName(kdm_xml.nsmap['dsig'], "X509IssuerName")).text = "dnQualifier=DHw+alRPNcyb+G1cNOAFjOgJTLk=,CN=.cc-wm-2337-001018,OU=CineCert RA,O=.ca-2.cinecert.com"
etree.SubElement(signer, etree.QName(kdm_xml.nsmap['dsig'], "X509SerialNumber")).text = "2977252096"

required_extensions = etree.SubElement(authenticated_public, "RequiredExtensions")
kdm_required_extensions = etree.SubElement(required_extensions, "KDMRequiredExtensions",
                                           nsmap={None: "http://www.smpte-ra.org/schemas/430-1/2006/KDM"})

recipient = etree.SubElement(kdm_required_extensions, "Recipient")
x509_issuer_serial = etree.SubElement(recipient, "X509IssuerSerial")
etree.SubElement(x509_issuer_serial, etree.QName(kdm_xml.nsmap['dsig'], "X509IssuerName")).text = "dnQualifier=BnB0iDJLgyqiWUjn1uqrOy2/DEE=,CN=.US1.DCS.DOLPHIN.DC2.SMPTE,OU=DC.DOREMILABS.COM,O=DC2.SMPTE.DOREMILABS.COM"
etree.SubElement(x509_issuer_serial, etree.QName(kdm_xml.nsmap['dsig'], "X509SerialNumber")).text = "87752988973791680"
etree.SubElement(recipient, "X509SubjectName").text = "dnQualifier=ztEtGF+XEyu/3qdbbOlzhRvkPik=,CN=LE SPB MD FM SM.IMB-228398.DC.DOLPHIN.DC2.SMPTE,OU=DC.DOREMILABS.COM,O=DC2.SMPTE.DOREMILABS.COM"

etree.SubElement(kdm_required_extensions, "CompositionPlaylistId").text = composition_playlist_id
etree.SubElement(kdm_required_extensions, "ContentTitleText").text = content_title_text
etree.SubElement(kdm_required_extensions, "ContentKeysNotValidBefore").text = content_keys_not_valid_before
etree.SubElement(kdm_required_extensions, "ContentKeysNotValidAfter").text = content_keys_not_valid_after

authorized_device_info = etree.SubElement(kdm_required_extensions, "AuthorizedDeviceInfo")
etree.SubElement(authorized_device_info, "DeviceListIdentifier").text = "urn:uuid:2d45be58-2a5d-4675-9caf-41ea39d878d4"
device_list = etree.SubElement(authorized_device_info, "DeviceList")
etree.SubElement(device_list, "CertificateThumbprint").text = "2jmj7l5rSw0yVb/vlWAYkK/YBwk="

key_id_list = etree.SubElement(kdm_required_extensions, "KeyIdList")
key_types = [("MDIK", "urn:uuid:c88fca4d-5cbc-4c3a-a857-e4c01b11cfb9"),
             ("MDAK", "urn:uuid:de6a84bb-33b1-4f98-bbc3-b73be6913df8")]

for key_type, key_id in key_types:
    typed_key_id = etree.SubElement(key_id_list, "TypedKeyId")
    etree.SubElement(typed_key_id, "KeyType").text = key_type
    etree.SubElement(typed_key_id, "KeyId").text = key_id

# Ajouter les clés chiffrées
authenticated_private = etree.SubElement(kdm_xml, "AuthenticatedPrivate", Id="ID_AuthenticatedPrivate")

for key_type, key_id in key_types:
    encrypted_key = etree.SubElement(authenticated_private, etree.QName(kdm_xml.nsmap['enc'], "EncryptedKey"))
    etree.SubElement(encrypted_key, etree.QName(kdm_xml.nsmap['enc'], "EncryptionMethod"), Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
    etree.SubElement(encrypted_key, etree.QName(kdm_xml.nsmap['dsig'], "DigestMethod"), Algorithm="http://www.w3.org/2000/09/xmldsig#sha1")

    # Chiffrer la clé de contenu avec la clé publique RSA du destinataire
    cipher_rsa = PKCS1_OAEP.new(key_recipient.publickey())
    content_key = get_random_bytes(16)  # Exemple de clé de contenu AES
    encrypted_content_key = cipher_rsa.encrypt(content_key)
    etree.SubElement(encrypted_key, etree.QName(kdm_xml.nsmap['enc'], "CipherData")).text = b64encode(encrypted_content_key).decode('utf-8')

# Signer le KDM avec la clé privée RSA de l'émetteur
signature = etree.SubElement(kdm_xml, etree.QName(kdm_xml.nsmap['dsig'], "Signature"))
# etree.QName(kdm_xml.nsmap['dsig'], "SignatureMethod")).text
signed_info = etree.SubElement(signature, etree.QName(kdm_xml.nsmap['dsig'], "SignedInfo"))
etree.SubElement(signed_info, etree.QName(kdm_xml.nsmap['dsig'], "CanonicalizationMethod"), Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")
etree.SubElement(signed_info, etree.QName(kdm_xml.nsmap['dsig'], "SignatureMethod"), Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

# Ajouter les références pour les parties publiques et privées
# etree.QName(kdm_xml.nsmap['dsig'], "DigestValue")
reference_public = etree.SubElement(signed_info, etree.QName(kdm_xml.nsmap['dsig'], "Reference"), URI="#ID_AuthenticatedPublic")
etree.SubElement(reference_public, etree.QName(kdm_xml.nsmap['dsig'], "DigestMethod"), Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
etree.SubElement(reference_public, etree.QName(kdm_xml.nsmap['dsig'], "DigestValue")).text = b64encode(SHA256.new(etree.tostring(authenticated_public)).digest()).decode('utf-8')

# etree.QName(kdm_xml.nsmap['dsig'], "Reference")
reference_private = etree.SubElement(signed_info, etree.QName(kdm_xml.nsmap['dsig'], "Reference"), URI="#ID_AuthenticatedPrivate")
etree.SubElement(reference_private, etree.QName(kdm_xml.nsmap['dsig'], "DigestMethod"), Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
etree.SubElement(reference_private, etree.QName(kdm_xml.nsmap['dsig'], "DigestValue")).text = b64encode(SHA256.new(etree.tostring(authenticated_private)).digest()).decode('utf-8')

# Ajouter la valeur de la signature
# etree.QName(kdm_xml.nsmap['dsig'], "SignatureValue")
signature_value = pkcs1_15.new(key_issuer).sign(SHA256.new(etree.tostring(signed_info)))
etree.SubElement(signature, etree.QName(kdm_xml.nsmap['dsig'], "SignatureValue")).text = b64encode(signature_value).decode('utf-8')

# Ajouter les informations de certificat
# etree.QName(kdm_xml.nsmap['dsig'], "X509IssuerSerial")
key_info = etree.SubElement(signature, etree.QName(kdm_xml.nsmap['dsig'], "KeyInfo"))
x509_data = etree.SubElement(key_info, etree.QName(kdm_xml.nsmap['dsig'], "X509Data"))
x509_issuer_serial = etree.SubElement(x509_data, etree.QName(kdm_xml.nsmap['dsig'], "X509IssuerSerial"))
etree.SubElement(x509_issuer_serial, etree.QName(kdm_xml.nsmap['dsig'], "X509IssuerName")).text = "dnQualifier=DHw+alRPNcyb+G1cNOAFjOgJTLk=,CN=.cc-wm-2337-001018,OU=CineCert RA,O=.ca-2.cinecert.com"
etree.SubElement(x509_issuer_serial, etree.QName(kdm_xml.nsmap['dsig'], "X509SerialNumber")).text = "2977252096"

# Afficher le KDM final
print(etree.tostring(kdm_xml, pretty_print=True).decode('utf-8'))
