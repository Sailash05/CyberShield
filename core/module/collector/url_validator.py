from urllib.parse import urlparse, urlunparse
import socket
import ipaddress


class URLValidator:

    def __init__(self, url: str):
        self.original_url = url.strip()

    def validate(self):
        result = {
            "original_url": self.original_url,
            "normalized_url": None,
            "scheme": None,
            "hostname": None,
            "port": None,
            "path": None,
            "query": None,
            "is_https": False,
            "is_ip": False,
            "is_private_ip": False,
            "dns_resolves": False,
            "resolved_ip": None,
            "valid": False,
            "severity": "Critical",
            "errors": []
        }

        url = self.original_url

        # Add https if scheme missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)

        # -----------------------------
        # Scheme Validation
        # -----------------------------
        if parsed.scheme not in ("http", "https"):
            result["errors"].append("Unsupported URL scheme.")
            return result

        result["scheme"] = parsed.scheme
        result["is_https"] = parsed.scheme == "https"

        # -----------------------------
        # Hostname Validation
        # -----------------------------
        hostname = parsed.hostname

        if hostname is None:
            result["errors"].append("Hostname missing.")
            return result

        result["hostname"] = hostname.lower()

        # -----------------------------
        # Port
        # -----------------------------
        result["port"] = parsed.port

        if result["port"] is None:
            result["port"] = 443 if parsed.scheme == "https" else 80

        # -----------------------------
        # Path & Query
        # -----------------------------
        result["path"] = parsed.path if parsed.path else "/"
        result["query"] = parsed.query

        # -----------------------------
        # Normalize URL
        # -----------------------------
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            result["path"],
            "",
            parsed.query,
            ""
        ))

        result["normalized_url"] = normalized

        # -----------------------------
        # URL Length
        # -----------------------------
        if len(normalized) > 2048:
            result["errors"].append("URL exceeds maximum length.")

        # -----------------------------
        # Localhost Check
        # -----------------------------
        if hostname.lower() == "localhost":
            result["errors"].append("Localhost scanning is not allowed.")

        # -----------------------------
        # IP Address Detection
        # -----------------------------
        try:
            ip = ipaddress.ip_address(hostname)

            result["is_ip"] = True

            if ip.is_private:
                result["is_private_ip"] = True
                result["errors"].append("Private IP scanning is not allowed.")

            result["resolved_ip"] = str(ip)

        except ValueError:

            # -------------------------
            # DNS Resolution
            # -------------------------
            try:
                resolved = socket.gethostbyname(hostname)

                result["dns_resolves"] = True
                result["resolved_ip"] = resolved

                ip = ipaddress.ip_address(resolved)

                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                    result["is_private_ip"] = True
                    result["errors"].append("Domain resolves to a private IP.")

            except socket.gaierror:
                result["errors"].append("DNS resolution failed.")

        # -----------------------------
        # Final Decision
        # -----------------------------
        if len(result["errors"]) == 0:
            result["valid"] = True

            if result["is_https"]:
                result["severity"] = "Low"
            else:
                result["severity"] = "Medium"

        return result


if __name__ == "__main__":

    validator = URLValidator("https://example.com/login?id=10")

    report = validator.validate()

    from pprint import pprint
    pprint(report)
