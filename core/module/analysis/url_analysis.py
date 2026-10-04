from module.collector.url_validator import URLValidator

def analyze_url(url_data):
    findings = []

    if not url_data.get("valid"):
        findings.append({
            "title": "Invalid or Unsafe URL",
            "severity": "Critical",
            "status": "Blocked",
            "description": "The URL failed validation and should not be scanned."
        })

        for error in url_data.get("errors", []):
            findings.append({
                "title": "URL Validation Error",
                "severity": "High",
                "status": "Detected",
                "description": error
            })

        return {
            "url": url_data.get("original_url"),
            "normalized_url": url_data.get("normalized_url"),
            "findings": findings
        }

    # HTTPS
    if url_data.get("is_https"):
        findings.append({
            "title": "HTTPS Enabled",
            "severity": "Informational",
            "status": "Secure",
            "description": "The URL uses HTTPS."
        })
    else:
        findings.append({
            "title": "HTTPS Not Enabled",
            "severity": "Medium",
            "status": "Warning",
            "description": "The URL uses HTTP instead of HTTPS."
        })

    # IP address
    if url_data.get("is_ip"):
        findings.append({
            "title": "IP Address Used in URL",
            "severity": "Low",
            "status": "Detected",
            "description": "The URL directly uses an IP address instead of a domain name."
        })
    else:
        findings.append({
            "title": "Domain Name Used",
            "severity": "Informational",
            "status": "Normal",
            "description": "The URL uses a domain name."
        })

    # Private IP
    if url_data.get("is_private_ip"):
        findings.append({
            "title": "Private or Reserved IP Address",
            "severity": "Critical",
            "status": "Blocked",
            "description": "The hostname resolves to a private, loopback, link-local, multicast, reserved, or unspecified IP address."
        })

    # DNS resolution
    if url_data.get("dns_resolves"):
        findings.append({
            "title": "DNS Resolution",
            "severity": "Informational",
            "status": "Successful",
            "description": f"Hostname resolves to {url_data.get('resolved_ip')}."
        })
    else:
        findings.append({
            "title": "DNS Resolution",
            "severity": "High",
            "status": "Failed",
            "description": "The hostname could not be resolved through DNS."
        })

    # Non-standard port
    scheme = url_data.get("scheme")
    port = url_data.get("port")

    standard_port = 443 if scheme == "https" else 80

    if port != standard_port:
        findings.append({
            "title": "Non-Standard Port",
            "severity": "Low",
            "status": "Detected",
            "description": f"The URL uses non-standard port {port}."
        })
    else:
        findings.append({
            "title": "Standard Port",
            "severity": "Informational",
            "status": "Normal",
            "description": f"The URL uses the standard {scheme.upper()} port {port}."
        })

    # URL length
    normalized_url = url_data.get("normalized_url", "")

    if len(normalized_url) > 2048:
        findings.append({
            "title": "Excessive URL Length",
            "severity": "Medium",
            "status": "Detected",
            "description": "The URL exceeds the recommended maximum length of 2048 characters."
        })
    else:
        findings.append({
            "title": "URL Length",
            "severity": "Informational",
            "status": "Normal",
            "description": "The URL length is within the expected range."
        })

    return {
        "url": url_data.get("original_url"),
        "normalized_url": normalized_url,
        "hostname": url_data.get("hostname"),
        "findings": findings
    }


def get_url_data(url: str):

    collector = URLValidator(url)

    data = collector.validate()

    result = analyze_url(data)

    return result