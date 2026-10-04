import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SslCollector:

    def __init__(self, domain):
        self.domain = domain

    def check_ssl(self):
        context = ssl.create_default_context()

        try:
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:

                    cert = ssock.getpeercert()

                    expiry = datetime.strptime(
                cert["notAfter"],
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

                    issuer = dict(x[0] for x in cert["issuer"])

                    der = ssock.getpeercert(binary_form=True)

                    certificate = x509.load_der_x509_certificate(
                        der,
                        default_backend()
                    )

                    version = certificate.version

                    cipher = ssock.cipher()

                    remaining = (expiry - datetime.now(timezone.utc)).days

                    return {
                "Domain": self.domain,
                "Issuer": issuer,
                "Subject": dict(x[0] for x in cert["subject"]),
                "Expiry": expiry.isoformat(),
                "Days Remaining": remaining,
                "Version": str(version),
                "Cipher": cipher[0],
                "TLS Version": cipher[1],
                "Key Size": cipher[2]
            }

        except Exception as e:
            return {"Error": str(e)}


# if __name__ == "__main__":
#     from pprint import pprint
    
#     collector = SslCollector("example.com")

#     pprint(collector.check_ssl())