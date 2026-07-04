import socket
import ssl
import logging
from typing import List
from cryptography import x509

logger = logging.getLogger("sentinel.ssl_extractor")

def extract_sans(host: str, port: int = 443) -> List[str]:
    """
    Extracts Subject Alternative Names (SANs) from the SSL/TLS certificate of a host.
    """
    sans = []
    try:
        # Create an insecure context because we just want the certificate, not authentication/verification.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return []
                cert = x509.load_der_x509_certificate(der_cert)
                try:
                    ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
                    san_ext = ext.value
                    dns_names = san_ext.get_values_for_type(x509.DNSName)
                    sans.extend(dns_names)
                except x509.ExtensionNotFound:
                    pass
    except Exception as e:
        logger.debug("Failed to extract SANs for %s:%d: %s", host, port, e)
    return list(set(sans))
